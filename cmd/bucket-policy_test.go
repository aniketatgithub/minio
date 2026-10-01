// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/minio/minio/internal/auth"
	"github.com/minio/pkg/v3/policy"
)

// Regression test for https://github.com/minio/minio/issues/21735
//
// A policy statement with `"Condition": {"Null": {"s3:versionid": "true"}}`
// must allow requests that carry no version ID (e.g. DeleteMultipleObjects
// without per-object VersionIDs) and deny requests that do carry one.
//
// getConditionValues() used to always inject a "versionid" condition value,
// even when the request had no version ID, so the Null condition could never
// evaluate to true and such policies always denied.
func TestGetConditionValuesVersionIDNullCondition(t *testing.T) {
	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["s3:DeleteObject"],
			"Resource": ["arn:aws:s3:::test/*"],
			"Condition": {"Null": {"s3:versionid": "true"}}
		}]
	}`

	var p policy.Policy
	if err := json.Unmarshal([]byte(policyJSON), &p); err != nil {
		t.Fatalf("unable to parse test policy: %v", err)
	}

	isAllowed := func(req *http.Request) bool {
		req.ParseForm()
		return p.IsAllowed(policy.Args{
			AccountName:     "testuser",
			Action:          policy.DeleteObjectAction,
			BucketName:      "test",
			ObjectName:      "obj",
			ConditionValues: getConditionValues(req, "", auth.AnonymousCredentials),
		})
	}

	// Multi-delete style request: POST /test/?delete, no versionId anywhere
	// (per-object version IDs live in the XML body, not the query string).
	multiDeleteReq := httptest.NewRequest(http.MethodPost, "https://s3.example/test/?delete",
		strings.NewReader(`<Delete><Object><Key>obj</Key></Object></Delete>`))
	if !isAllowed(multiDeleteReq) {
		t.Fatal("expected s3:DeleteObject to be allowed when the request carries no version ID (Null s3:versionid=true)")
	}

	// Same request shape but with an explicit versionId in the query string
	// must still be denied by the Null condition.
	versionedReq := httptest.NewRequest(http.MethodDelete, "https://s3.example/test/obj", nil)
	versionedReq.Form = url.Values{"versionId": {"d5f8f35c-8c3a-4e1f-9e4e-123456789abc"}}
	if isAllowed(versionedReq) {
		t.Fatal("expected s3:DeleteObject to be denied when the request carries a version ID (Null s3:versionid=true)")
	}
}
