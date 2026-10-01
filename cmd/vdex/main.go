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
	path := fs.String("package", "package.json", "package file to verify")
	dataset := fs.String("dataset", "", "REQUIRED trusted dataset name expected in the package")
	version := fs.Uint64("version", 0, "REQUIRED trusted sealed version number")
	rootHex := fs.String("root", "", "REQUIRED trusted Merkle root (hex), e.g. from 'seal' output")
	indicesFlag := fs.String("indices", "", "REQUIRED comma-separated indices the receiver asked for, e.g. 0,3,7")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pkg, err := vdex.ReadPackage(*path)
	if err != nil {
		return err
	}
	if *dataset == "" || *version == 0 || *rootHex == "" || *indicesFlag == "" {
		return errors.New("verify requires -dataset, -version, -root and -indices; values inside the package are not trusted")
	}
	rootBytes, err := hex.DecodeString(strings.TrimPrefix(*rootHex, "0x"))
	if err != nil || len(rootBytes) != 32 {
		return fmt.Errorf("-root must be a 32-byte hex digest: %w", err)
	}
	var wantRoot vdex.Hash
	copy(wantRoot[:], rootBytes)
	var wantIndices []uint64
	for _, part := range strings.Split(*indicesFlag, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		i, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return fmt.Errorf("bad expected index %q: %w", part, err)
		}
		wantIndices = append(wantIndices, i)
	}
	r := vdex.VerifyPackage(pkg, vdex.Expectation{
		Dataset: *dataset,
		Version: *version,
		Root:    wantRoot,
		Indices: wantIndices,
	})
	status := "INVALID"
	if r.Valid {
		status = "VALID"
	}
	fmt.Printf("%s  dataset=%s version=%d root=%s matched=%d/%d expected=%v present=%v\n",
		status, r.Dataset, r.Version, hex.EncodeToString(r.Root[:]), r.Matched, len(r.Expected), r.Expected, r.Present)
	for _, e := range r.Errors {
		fmt.Fprintln(os.Stderr, "  -", e)
	}
	if !r.Valid {
		return errVerification
	}
	return nil
}

func openInput(path string) (io.ReadCloser, error) {
	if path == "-" {
		return os.Stdin, nil
	}
	return os.Open(path)
}
