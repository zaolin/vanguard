package main

import (
	"github.com/alecthomas/kong"
)

func main() {
	var cli CLI
	ctx := kong.Parse(&cli,
		kong.Name("vanguard"),
		kong.Description("A minimal initrd generator for encrypted LVM root with TPM2 support"),
		kong.UsageOnError(),
		kong.Vars{"version": Version},
	)
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}
