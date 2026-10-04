package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"vdex/internal/vdex"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "vdex:", err)
		if errors.Is(err, errVerification) {
			os.Exit(1)
		}
		os.Exit(2)
	}
}

var errVerification = errors.New("verification failed")

func usage() {
	fmt.Fprintln(os.Stderr, `usage: vdex <command> [flags]

commands:
  seal     seal a JSONL dataset into a new immutable version
  versions list sealed versions
  extract  export a subset of records with inclusion proofs
  verify   independently verify an exported package`)
}

func run(cmd string, args []string) error {
	switch cmd {
	case "seal":
		return cmdSeal(args)
	case "versions":
		return cmdVersions(args)
	case "extract":
		return cmdExtract(args)
	case "verify":
		return cmdVerify(args)
	default:
		usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func cmdSeal(args []string) error {
	fs := flag.NewFlagSet("seal", flag.ContinueOnError)
	storeDir := fs.String("store", "./vdex-store", "version store directory")
	dataset := fs.String("dataset", "default", "dataset name recorded in the manifest")
	input := fs.String("input", "-", "JSONL input file ('-' for stdin)")
	expect := fs.Uint64("expect-next", 0, "fail unless this is the next version number")
	if err := fs.Parse(args); err != nil {
		return err
	}
	f, err := openInput(*input)
	if err != nil {
		return err
	}
	defer f.Close()
	m, err := vdex.NewStore(*storeDir).Seal(*dataset, f, *expect, time.Now())
	if err != nil {
		return err
	}
	fmt.Printf("sealed %s v%d  id=%s  root=%s  records=%d\n",
		m.Dataset, m.Version, m.VersionID(), hex.EncodeToString(m.Root[:]), m.LeafCount)
	return nil
}

func cmdVersions(args []string) error {
	fs := flag.NewFlagSet("versions", flag.ContinueOnError)
	storeDir := fs.String("store", "./vdex-store", "version store directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ms, err := vdex.NewStore(*storeDir).Versions()
	if err != nil {
		return err
	}
	if len(ms) == 0 {
		fmt.Println("no sealed versions")
		return nil
	}
	for _, m := range ms {
		prev := "-"
		if m.Prev != nil {
			prev = hex.EncodeToString((*m.Prev)[:8])
		}
		fmt.Printf("v%-4d id=%s records=%d sealedAt=%s prev=%s\n",
			m.Version, m.VersionID(), m.LeafCount, m.SealedAt.Format(time.RFC3339), prev)
	}
	return nil
}

func cmdExtract(args []string) error {
	fs := flag.NewFlagSet("extract", flag.ContinueOnError)
	storeDir := fs.String("store", "./vdex-store", "version store directory")
	version := fs.Uint64("version", 0, "version to extract from (default: latest)")
	indicesFlag := fs.String("indices", "", "comma-separated record indices, e.g. 0,3,7")
	out := fs.String("out", "package.json", "output package path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	store := vdex.NewStore(*storeDir)
	v := *version
	if v == 0 {
		latest, err := store.LatestVersion()
		if err != nil {
			return err
		}
		if latest == 0 {
			return errors.New("store has no sealed versions")
		}
		v = latest
	}
	if *indicesFlag == "" {
		return errors.New("-indices is required")
	}
	var indices []uint64
	for _, part := range strings.Split(*indicesFlag, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		i, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return fmt.Errorf("bad index %q: %w", part, err)
		}
		indices = append(indices, i)
	}
	pkg, err := store.Extract(v, indices)
	if err != nil {
		return err
	}
	if err := vdex.WritePackage(*out, pkg); err != nil {
		return err
	}
	fmt.Printf("wrote %d entries from v%d to %s\n", len(pkg.Entries), v, *out)
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	var paths stringList
	fs.Var(&paths, "package", "package file to verify (repeatable: batches of one request may arrive separately)")
	dataset := fs.String("dataset", "", "trusted dataset name the package must claim")
	version := fs.Uint64("version", 0, "trusted version number the package must claim")
	rootHex := fs.String("root", "", "trusted version root (hex) from a source the receiver already trusts")
	indicesFlag := fs.String("indices", "", "comma-separated record indices expected in the package")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(paths) == 0 {
		return errors.New("-package is required")
	}
	if *dataset == "" {
		return errors.New("-dataset is required: the receiver must name the trusted dataset")
	}
	if *version == 0 {
		return errors.New("-version is required: the receiver must name the trusted version")
	}
	if *rootHex == "" {
		return errors.New("-root is required: without a trusted root the package only proves its own self-consistency")
	}
	var req vdex.Request
	req.Dataset = *dataset
	req.Version = *version
	raw, err := hex.DecodeString(*rootHex)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("bad -root: expected 64 hex chars")
	}
	var h vdex.Hash
	copy(h[:], raw)
	req.Root = &h
	if *indicesFlag == "" {
		return errors.New("-indices is required: the receiver must state the expected record set")
	}
	for _, part := range strings.Split(*indicesFlag, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		i, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return fmt.Errorf("bad index %q: %w", part, err)
		}
		req.Indices = append(req.Indices, i)
	}
	session, err := vdex.NewSession(req)
	if err != nil {
		return err
	}
	for _, p := range paths {
		pkg, err := vdex.ReadPackage(p)
		if err != nil {
			return err
		}
		session.Add(pkg)
	}
	st := session.Status()
	status := "INCOMPLETE"
	switch {
	case st.Complete:
		status = "VALID"
	case len(st.Conflicts) > 0 || len(st.Rejected) > 0:
		status = "INVALID"
	}
	fmt.Printf("%s  dataset=%s version=%d root=%s verified=%d missing=%d duplicates=%d\n",
		status, req.Dataset, req.Version, hex.EncodeToString(h[:]),
		len(st.Verified), len(st.Missing), st.Duplicates)
	for _, i := range st.Missing {
		fmt.Fprintln(os.Stderr, "  - missing required record at index", i)
	}
	for _, c := range st.Conflicts {
		fmt.Fprintf(os.Stderr, "  - conflicting material at index %d (x%d): accepted %s (batch %d), later arrival %s (batch %d): %s\n",
			c.Index, c.Count, c.Accepted, c.AcceptedBatch, c.Rejected, c.RejectedBatch, c.Reason)
	}
	for _, e := range st.Rejected {
		if e.Index != nil {
			fmt.Fprintf(os.Stderr, "  - batch %d index %d (x%d): %s; kept record: %s\n",
				e.Batch, *e.Index, e.Count, e.Reason, e.Record)
		} else {
			fmt.Fprintf(os.Stderr, "  - batch %d (x%d): %s\n", e.Batch, e.Count, e.Reason)
		}
	}
	if !st.Complete {
		return errVerification
	}
	return nil
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func openInput(path string) (io.ReadCloser, error) {
	if path == "-" {
		return os.Stdin, nil
	}
	return os.Open(path)
}
