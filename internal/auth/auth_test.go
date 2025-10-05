package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name:          "valid API key",
			headers:       http.Header{"Authorization": []string{"ApiKey abc123"}},
			expectedKey:   "abc123",
			expectedError: nil,
		},
		{
			name:          "no authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "empty authorization header",
			headers:       http.Header{"Authorization": []string{""}},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "malformed header - missing ApiKey prefix",
			headers:       http.Header{"Authorization": []string{"Bearer abc123"}},
			expectedKey:   "",
			expectedError: nil, // Will be "malformed authorization header" error
		},
		{
			name:          "malformed header - only ApiKey without key",
			headers:       http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey:   "",
			expectedError: nil, // Will be "malformed authorization header" error
		},
		{
			name:          "malformed header - no space",
			headers:       http.Header{"Authorization": []string{"ApiKeyabc123"}},
			expectedKey:   "",
			expectedError: nil, // Will be "malformed authorization header" error
		},
		{
			name:          "valid API key with extra spaces",
			headers:       http.Header{"Authorization": []string{"ApiKey abc123 extra"}},
			expectedKey:   "abc123",
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tt.headers)

			// Check the returned key
			if gotKey != tt.expectedKey {
				t.Errorf("GetAPIKey() key = %v, want %v", gotKey, tt.expectedKey)
			}

			// Check for expected errors
			if tt.expectedError != nil {
				if gotErr == nil {
					t.Errorf("GetAPIKey() error = nil, want %v", tt.expectedError)
				} else if gotErr.Error() != tt.expectedError.Error() {
					t.Errorf("GetAPIKey() error = %v, want %v", gotErr, tt.expectedError)
				}
			} else {
				// For malformed header cases, we expect a specific error message
				if tt.name == "malformed header - missing ApiKey prefix" ||
					tt.name == "malformed header - only ApiKey without key" ||
					tt.name == "malformed header - no space" {
					if gotErr == nil || gotErr.Error() != "malformed authorization header" {
						t.Errorf("GetAPIKey() error = %v, want 'malformed authorization header'", gotErr)
					}
				} else if gotErr != nil {
					t.Errorf("GetAPIKey() error = %v, want nil", gotErr)
				}
			}
		})
	}
}
