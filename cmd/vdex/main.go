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
  seal      seal a JSONL dataset into a new immutable version
  versions  list sealed versions
  extract   export a subset of records with inclusion proofs
  verify    independently verify an exported package
  decisions list archived verification decisions`)
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
	case "decisions":
		return cmdDecisions(args)
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
	decisionsDir := fs.String("decisions", "", "decision archive directory: resume prior batches and save this decision")
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
	var session *vdex.Session
	if *decisionsDir != "" {
		var resumed bool
		session, resumed, err = vdex.NewDecisionStore(*decisionsDir).Open(req)
		if err != nil {
			return err
		}
		if resumed {
			fp := session.Fingerprint()
			fmt.Fprintf(os.Stderr, "resuming archived decision %x\n", fp[:12])
		}
	} else {
		session, err = vdex.NewSession(req)
		if err != nil {
			return err
		}
	}
	for _, p := range paths {
		pkg, err := vdex.ReadPackage(p)
		if err != nil {
			return err
		}
		session.Add(pkg)
	}
	st := session.Status()
	if *decisionsDir != "" {
		if _, err := vdex.NewDecisionStore(*decisionsDir).Save(session); err != nil {
			return err
		}
	}
	status := "INCOMPLETE"
	switch {
	case st.Complete:
		status = "VALID"
	case len(st.Conflicts) > 0 || len(st.Refused) > 0:
		status = "INVALID"
	}
	fmt.Printf("%s  dataset=%s version=%d root=%s verified=%d missing=%d conflicted=%d duplicates=%d\n",
		status, req.Dataset, req.Version, hex.EncodeToString(h[:]),
		len(st.Verified), len(st.Missing), len(st.Conflicted), st.Duplicates)
	for _, i := range st.Missing {
		fmt.Fprintln(os.Stderr, "  - missing required record at index", i)
	}
	for _, c := range st.Conflicts {
		fmt.Fprintf(os.Stderr, "  - conflict at index %d: accepted batch %d %s (%s)\n",
			c.Index, c.Accepted.Batch, c.Accepted.Record, c.Accepted.Basis)
		for _, ev := range c.Disputed {
			fmt.Fprintf(os.Stderr, "      disputed batch %d: %s (%s)\n", ev.Batch, ev.Record, ev.Basis)
		}
		if c.Repeats > 0 {
			fmt.Fprintf(os.Stderr, "      %d repeat delivery(ies) of identical disputed content\n", c.Repeats)
		}
	}
	for _, e := range st.Refused {
		switch {
		case e.Index != nil && len(e.Record) > 0:
			fmt.Fprintf(os.Stderr, "  - batch %d index %d original=%s: %s\n", e.Batch, *e.Index, e.Record, e.Basis)
		case e.Index != nil:
			fmt.Fprintf(os.Stderr, "  - batch %d index %d: %s\n", e.Batch, *e.Index, e.Basis)
		default:
			fmt.Fprintf(os.Stderr, "  - batch %d: %s\n", e.Batch, e.Basis)
		}
	}
	if !st.Complete {
		return errVerification
	}
	return nil
}

func cmdDecisions(args []string) error {
	fs := flag.NewFlagSet("decisions", flag.ContinueOnError)
	storeDir := fs.String("dir", "./vdex-decisions", "decision archive directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	decs, err := vdex.NewDecisionStore(*storeDir).List()
	if err != nil {
		return err
	}
	if len(decs) == 0 {
		fmt.Println("no archived decisions")
		return nil
	}
	for _, dec := range decs {
		st := "INCOMPLETE"
		switch {
		case dec.Complete:
			st = "VALID"
		case len(dec.Snapshot.Conflicts) > 0 || len(dec.Snapshot.Refused) > 0:
			st = "INVALID"
		}
		fmt.Printf("%s  id=%s dataset=%s version=%d indices=%v batches=%d\n",
			st, hex.EncodeToString(dec.Fingerprint[:12]),
			dec.Request.Dataset, dec.Request.Version, dec.Request.Indices, dec.Snapshot.Batches)
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
