// Copyright 2016 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package command

import (
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/spf13/cobra"
)

var (
	publicKeyPath  string
	privateKeyPath string
)

// NewAuthCommand returns the cobra command for "auth".
func NewAuthCommand() *cobra.Command {
	ac := &cobra.Command{
		Use:   "auth <enable or disable>",
		Short: "Enable or disable authentication.",
	}

	ac.AddCommand(newAuthEnableCommand())
	ac.AddCommand(newAuthSetKeysCommand())

	return ac
}

func newAuthEnableCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "enable",
		Short: "enable authentication",
		Run:   authEnableCommandFunc,
	}
}

func newAuthSetKeysCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set-keys",
		Short: "set keys for signing and verifying tokens",
		Run:   authSetKeysCommandFunc,
	}

	cmd.Flags().StringVar(&publicKeyPath, "public-key", "", "a path of public key used for verifying auth tokens")
	cmd.Flags().StringVar(&privateKeyPath, "private-key", "", "a path of private key used for signing auth tokens")

	return cmd
}

// authEnableCommandFunc executes the "auth enable" command.
func authEnableCommandFunc(cmd *cobra.Command, args []string) {
	if len(args) != 0 {
		ExitWithError(ExitBadArgs, fmt.Errorf("auth enable command does not accept argument."))
	}

	ctx, cancel := commandCtx(cmd)
	_, err := mustClientFromCmd(cmd).Auth.AuthEnable(ctx)
	cancel()
	if err != nil {
		ExitWithError(ExitError, err)
	}

	fmt.Println("Authentication Enabled")
}

// authSetKeysCommandFunc executes the "auth set-keys" command.
func authSetKeysCommandFunc(cmd *cobra.Command, args []string) {
	if strings.Compare(privateKeyPath, "") == 0 {
		ExitWithError(ExitBadArgs, fmt.Errorf("auth set-keys command requires a path of private key as --private-key.", privateKeyPath))
	}

	signBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		ExitWithError(ExitBadArgs, fmt.Errorf("a priv key file (%s) couldn't be read.", privateKeyPath))
	}

	if strings.Compare(publicKeyPath, "") == 0 {
		ExitWithError(ExitBadArgs, fmt.Errorf("auth set-keys command requires a path of public key as --public-key.", publicKeyPath))
	}

	verifyBytes, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		ExitWithError(ExitBadArgs, fmt.Errorf("a public key file (%s) couldn't be read.", publicKeyPath))
	}

	ctx, cancel := commandCtx(cmd)
	_, err = mustClientFromCmd(cmd).Auth.AuthSetKeys(ctx, signBytes, verifyBytes)
	cancel()
	if err != nil {
		ExitWithError(ExitError, err)
	}

	fmt.Println("Keys are initialized successfully")
}
