package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
)

// FilePart is one file in a multipart request.
type FilePart struct {
	Field    string // form field name
	FileName string
	Content  []byte
}

// DoMultipart sends a multipart/form-data request with plain fields and
// files, as Fleet Manager's bundle and file-manager uploads expect.
func (c *Client) DoMultipart(ctx context.Context, method, path string, fields map[string]string, files ...FilePart) (*Response, error) {
	body, contentType, err := multipartBody(fields, nil, files)
	if err != nil {
		return nil, err
	}
	return c.Do(ctx, method, path, nil, body, contentType)
}

// GraphQLUpload runs a GraphQL operation with one uploaded file, using the
// GraphQL multipart request convention: "operations", "map" and a file
// part named "1". filePath is where the file goes in the variables, for
// example "variables.input.file"; that variable must be null in vars.
func (c *Client) GraphQLUpload(ctx context.Context, query string, variables map[string]any, filePath, fileName string, content []byte) (*Response, error) {
	ops, err := json.Marshal(map[string]any{"query": query, "variables": variables})
	if err != nil {
		return nil, err
	}
	m, err := json.Marshal(map[string][]string{"1": {filePath}})
	if err != nil {
		return nil, err
	}
	// operations and map must precede the file part.
	order := [][2]string{{"operations", string(ops)}, {"map", string(m)}}
	body, contentType, err := multipartBody(nil, order, []FilePart{{Field: "1", FileName: fileName, Content: content}})
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(ctx, http.MethodPost, graphQLPath, nil, body, contentType)
	if err != nil && resp != nil && hasGraphQLErrors(resp.Body) {
		return resp, nil
	}
	return resp, err
}

func multipartBody(fields map[string]string, ordered [][2]string, files []FilePart) ([]byte, string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for _, kv := range ordered {
		if err := w.WriteField(kv[0], kv[1]); err != nil {
			return nil, "", err
		}
	}
	for k, v := range fields {
		if err := w.WriteField(k, v); err != nil {
			return nil, "", err
		}
	}
	for _, f := range files {
		part, err := w.CreateFormFile(f.Field, f.FileName)
		if err != nil {
			return nil, "", fmt.Errorf("multipart file %s: %w", f.FileName, err)
		}
		if _, err := part.Write(f.Content); err != nil {
			return nil, "", err
		}
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), w.FormDataContentType(), nil
}
