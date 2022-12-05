package gincloudflareaccess

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_mapIDPGroupsToCloudflareGroups(t *testing.T) {
	expectedErrBadFormat := "groups entry is not an array"
	expectedErrBadIDPFormat := "unknown format for IDP group entry"

	tests := []struct {
		input   string
		want    []CloudflareIdentityGroup
		wantErr string
	}{
		{input: `null`, want: []CloudflareIdentityGroup{}},
		{input: `[]`, want: []CloudflareIdentityGroup{}},
		{input: `{}`, wantErr: expectedErrBadFormat},
		{input: `123`, wantErr: expectedErrBadFormat},
		{input: `"aaa"`, wantErr: expectedErrBadFormat},
		{input: `[null]`, wantErr: expectedErrBadIDPFormat},
		{input: `[123]`, wantErr: expectedErrBadIDPFormat},
		{input: `[[]]`, wantErr: expectedErrBadIDPFormat},
		{input: `[{}]`, wantErr: expectedErrBadIDPFormat},
		{input: `[{"name": "just a name"}]`, wantErr: expectedErrBadIDPFormat},
		{input: `[{"another_field": 42}]`, wantErr: expectedErrBadIDPFormat},
		{
			input: `["group 1"]`,
			want: []CloudflareIdentityGroup{
				{Id: "group 1", Name: "group 1"},
			},
		},
		{
			input: `[{"id": "g1"}]`,
			want: []CloudflareIdentityGroup{
				{Id: "g1", Name: "g1"},
			},
		},
		{
			input: `[{"email": "G1@comp.com"}]`,
			want: []CloudflareIdentityGroup{
				{Id: "G1@comp.com", Name: "G1@comp.com", Email: "G1@comp.com"},
			},
		},
		{
			input: `[
				"G0", 
				{"id": "G1"}, 
				{"email": "G2@comp.com"}, 
				"G3",
				{"id": "G4", "name": "group 4"},
				{"id": "G5", "name": "group 5", "email": "G5@comp.com"},
				{"id": "G6", "email": "G6@comp.com"}
			]`,
			want: []CloudflareIdentityGroup{
				{Id: "G0", Name: "G0"},
				{Id: "G1", Name: "G1"},
				{Id: "G2@comp.com", Name: "G2@comp.com", Email: "G2@comp.com"},
				{Id: "G3", Name: "G3"},
				{Id: "G4", Name: "group 4"},
				{Id: "G5", Name: "group 5", Email: "G5@comp.com"},
				{Id: "G6", Name: "G6@comp.com", Email: "G6@comp.com"},
			},
		},
	}
	for i, tt := range tests {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			var unmarshalled interface{}

			err := json.Unmarshal([]byte(tt.input), &unmarshalled)
			assert.NoError(t, err)

			got, err := mapIDPGroupsToCloudflareGroups(unmarshalled)

			if tt.wantErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				assert.NoError(t, err)
			}

			assert.Equalf(t, tt.want, got, "mapIDPGroupsToCloudflareGroups(%v)", tt.input)
		})
	}
}
