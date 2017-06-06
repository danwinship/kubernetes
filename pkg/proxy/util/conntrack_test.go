/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package util

import (
	"fmt"
	"testing"

	"k8s.io/kubernetes/pkg/util/exec"
)

func TestExecConntrackTool(t *testing.T) {
	fexec := exec.FakeExec{
		LookPathFunc: func(cmd string) (string, error) { return cmd, nil },
		T: t,
	}

	testCases := [][]string{
		{"-L", "-p", "udp"},
		{"-D", "-p", "udp", "-d", "10.0.240.1"},
		{"-D", "-p", "udp", "--orig-dst", "10.240.0.2", "--dst-nat", "10.0.10.2"},
	}
	expectErr := []bool{false, false, true}

	for i := range testCases {
		if !expectErr[i] {
			fexec.AddCommand("conntrack", testCases[i]...).
				SetCombinedOutput("1 flow entries have been deleted", nil)
		} else {
			fexec.AddCommand("conntrack", testCases[i]...).
				SetCombinedOutput("", fmt.Errorf("conntrack v1.4.2 (conntrack-tools): 0 flow entries have been deleted."))
		}

		err := ExecConntrackTool(&fexec, testCases[i]...)

		if expectErr[i] {
			if err == nil {
				t.Errorf("expected err, got %v", err)
			}
		} else {
			if err != nil {
				t.Errorf("expected success, got %v", err)
			}
		}

		fexec.AssertExpectedCommands()
	}
}

func TestDeleteServiceConnections(t *testing.T) {
	fexec := exec.FakeExec{
		LookPathFunc: func(cmd string) (string, error) { return cmd, nil },
		T: t,
	}

	testCases := [][]string{
		{
			"10.240.0.3",
			"10.240.0.5",
		},
		{
			"10.240.0.4",
		},
	}
	expectErr := []bool{false, true}

	for i := range testCases {
		for _, ip := range testCases[i] {
			args := []string{"-D", "--orig-dst", ip, "-p", "udp"}
			if !expectErr[i] {
				fexec.AddCommand("conntrack", args...).
					SetCombinedOutput("1 flow entries have been deleted", nil)
			} else {
				fexec.AddCommand("conntrack", args...).
					SetCombinedOutput("", fmt.Errorf("conntrack v1.4.2 (conntrack-tools): 0 flow entries have been deleted."))
			}
		}				
		DeleteServiceConnections(&fexec, testCases[i])
		fexec.AssertExpectedCommands()
	}
}
