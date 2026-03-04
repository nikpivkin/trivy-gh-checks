package main

import (
	"os"

	"github.com/open-policy-agent/opa/cmd"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/types"
)

func main() {
	rego.RegisterBuiltin2(&rego.Function{
		Name: "result.new",
		Decl: types.NewFunction(types.Args(types.S, types.A), types.A),
	},
		createResult,
	)

	if err := cmd.RootCommand.Execute(); err != nil {
		os.Exit(1)
	}
}

func createResult(ctx rego.BuiltinContext, message, _ *ast.Term) (*ast.Term, error) {
	return ast.ObjectTerm(
		[2]*ast.Term{ast.StringTerm("msg"), message},
	), nil
}
