// Command vdx seals local datasets into fixed, append-only versions and lets a
// receiver independently verify partial records without any chain or object
// storage service.
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"

	"vdx/internal/bundle"
	"vdx/internal/manifest"
	"vdx/internal/merkle"
	"vdx/internal/repo"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "publish":
		err = cmdPublish(os.Args[2:])
	case "export":
		err = cmdExport(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "info":
		err = cmdInfo(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "vdx: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `vdx - verifiable local data exchange

Usage:
  vdx init     --repo DIR [--dataset-id ID]
  vdx publish  --repo DIR --records FILE
  vdx export   --repo DIR --version N --start I --end E --out DIR
  vdx verify   --bundle DIR --root HEX [--dataset-id ID] [--version N] [--report FILE]
  vdx info     --repo DIR

Records files are canonical JSONL: one record per line, LF newlines, file
must end with a newline. Versions are append-only; publishing never mutates a
previously sealed version and is interrupted without advancing the head.
`)
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	dir := fs.String("repo", "", "repository directory")
	ds := fs.String("dataset-id", "", "stable dataset identity (default: random)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("--repo is required")
	}
	r, err := repo.Init(*dir, *ds)
	if err != nil {
		return err
	}
	h := r.Head()
	fmt.Printf("initialized empty repository %s\n  dataset_id: %s\n", *dir, h.DatasetID)
	return nil
}

func cmdPublish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	dir := fs.String("repo", "", "repository directory")
	file := fs.String("records", "", "canonical JSONL records file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *file == "" {
		return errors.New("--repo and --records are required")
	}
	r, err := repo.Open(*dir)
	if err != nil {
		return err
	}
	m, err := r.Publish(*file)
	if err != nil {
		return err
	}
	fmt.Printf("sealed v%d  records=%d  version_id=%s\n", m.Version, m.RecordCount, m.VersionID)
	if m.ParentVersionID != "" {
		fmt.Printf("previous version remains intact: %s\n", m.ParentVersionID)
	}
	return nil
}

func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	dir := fs.String("repo", "", "repository directory")
	ver := fs.Uint64("version", 0, "version to export (0 = current)")
	start := fs.Uint64("start", 0, "first record index (inclusive)")
	end := fs.Uint64("end", 0, "end index (exclusive); 0 = to the last record")
	out := fs.String("out", "", "output package directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *out == "" {
		return errors.New("--repo and --out are required")
	}
	r, err := repo.Open(*dir)
	if err != nil {
		return err
	}
	v := *ver
	if v == 0 {
		v = r.Head().Version
	}
	if v == 0 {
		return errors.New("repository has no sealed version")
	}
	m, err := r.LoadManifest(v)
	if err != nil {
		return err
	}
	recs, err := r.LoadRecords(v)
	if err != nil {
		return err
	}
	// Rebuild from the sealed payload and check it against the manifest anchor;
	// export refuses to hand out proofs from a corrupted local version.
	var root merkle.Hash
	leaves := make([]merkle.Hash, len(recs))
	for i, rec := range recs {
		leaves[i] = merkle.LeafHash(m.DatasetID, m.Version, uint64(i), rec)
	}
	if len(leaves) == 0 {
		root = merkle.EmptyRoot(m.DatasetID, m.Version)
	} else {
		root = merkle.Build(leaves).Root()
	}
	if hex.EncodeToString(root[:]) != m.VersionID {
		return fmt.Errorf("sealed version v%d fails local integrity check", v)
	}
	e := *end
	if e == 0 {
		e = uint64(len(recs))
	}
	d, err := bundle.Create(m, recs, merkle.Build(leaves), *start, e, *out)
	if err != nil {
		return err
	}
	fmt.Printf("exported %d/%d records [%d,%d) of v%d to %s\n  version_id: %s\n",
		d.IncludedCount, d.TotalRecords, d.StartIndex, d.StartIndex+d.IncludedCount, d.Version, *out, d.VersionID)
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	bundleDir := fs.String("bundle", "", "package directory to verify")
	rootHex := fs.String("root", "", "trusted version root (hex, 32 bytes)")
	ds := fs.String("dataset-id", "", "trusted dataset id (optional but recommended)")
	ver := fs.Uint64("version", 0, "trusted version number (0 = do not pin)")
	report := fs.String("report", "", "write the JSON verification report to this file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bundleDir == "" || *rootHex == "" {
		return errors.New("--bundle and --root are required")
	}
	raw, err := hex.DecodeString(*rootHex)
	if err != nil || len(raw) != 32 {
		return errors.New("--root must be 64 hex characters (SHA-256)")
	}
	var root merkle.Hash
	copy(root[:], raw)
	res, err := bundle.Verify(*bundleDir, *ds, *ver, root)
	if err != nil {
		return err
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
	if *report != "" {
		if err := os.WriteFile(*report, append(out, '\n'), 0o644); err != nil {
			return err
		}
	}
	if !res.OK {
		os.Exit(1)
	}
	return nil
}

func cmdInfo(args []string) error {
	fs := flag.NewFlagSet("info", flag.ContinueOnError)
	dir := fs.String("repo", "", "repository directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("--repo is required")
	}
	r, err := repo.Open(*dir)
	if err != nil {
		return err
	}
	h := r.Head()
	fmt.Printf("dataset_id: %s\ncurrent:    v%s  records=%d\nroot:       %s\n",
		h.DatasetID, strconv.FormatUint(h.Version, 10), h.RecordCount, h.VersionID)
	if h.Version == 0 {
		fmt.Println("(no sealed version yet)")
	}
	_ = manifest.VersionDir
	return nil
}
