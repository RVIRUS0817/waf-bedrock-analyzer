package main

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/athena"
)

// runAthenaQuery executes an Athena query and retrieves the results
func runAthenaQuery(ctx context.Context, query string) (string, []*athena.Row, string, string) {
	// Basic SQL injection check (simplified implementation)
	if strings.Contains(strings.ToUpper(query), "DROP") ||
		strings.Contains(strings.ToUpper(query), "DELETE") ||
		strings.Contains(strings.ToUpper(query), "INSERT") ||
		strings.Contains(strings.ToUpper(query), "UPDATE") {
		return "", nil, "Invalid SQL command detected", ""
	}

	query = preprocessSqlQuery(query)

	// Detect region from query and get appropriate Athena client
	region := getQueryRegion(query)
	client := getAthenaClient(region)
	log.Printf("Executing query (region: %s)", region)

	// Build S3 bucket path (based on region)
	s3Path := fmt.Sprintf("s3://%s/", athenaOutput)
	if region == "us-east-1" && strings.Contains(athenaOutput, "ap-northeast-1") {
		// Replace region part in bucket name
		s3Path = strings.Replace(s3Path, "ap-northeast-1", "us-east-1", 1)

		// Fix bucket name - use correct bucket name for us-east-1
		// Get correct bucket name from IAM policy specified in lambda.tf
		if strings.Contains(s3Path, "xxx") {
			s3Path = strings.Replace(s3Path, "xxx", "xxx", 1)
		}

		log.Printf("Adjusted S3 path for us-east-1: %s", s3Path)
	}

	// Adjust database name based on region before query execution
	dbName := athenaDB
	// Separate table name from database name (in case of dot separation)
	dbParts := strings.Split(dbName, ".")
	dbNameOnly := dbParts[0]

	if region == "us-east-1" {
		// Replace database name for us-east-1 region
		dbNameOnly = strings.Replace(dbNameOnly, "ap_northeast_1", "us_east_1", -1)
		dbNameOnly = strings.Replace(dbNameOnly, "ap-northeast-1", "us-east-1", -1)
		log.Printf("Adjusted database name for us-east-1: %s", dbNameOnly)
	}

	log.Printf("Using database name: %s", dbNameOnly)

	out, err := client.StartQueryExecution(&athena.StartQueryExecutionInput{
		QueryString: aws.String(query),
		QueryExecutionContext: &athena.QueryExecutionContext{
			Database: aws.String(dbNameOnly),
		},
		ResultConfiguration: &athena.ResultConfiguration{
			OutputLocation: aws.String(s3Path),
		},
		WorkGroup: aws.String(athenaWorkgroup),
	})
	if err != nil {
		errMsg := fmt.Sprintf("Athena start error: %v", err)
		log.Printf(errMsg)
		return "", nil, errMsg, region
	}

	qid := *out.QueryExecutionId
	log.Printf("Started Athena query with ID: %s", qid)

	// Query timeout setting (45 seconds) - set sufficiently shorter than overall Lambda timeout
	queryTimeout := 45 * time.Second
	queryContext, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	// Channel for timeout monitoring
	doneCh := make(chan struct{})
	var errorMsg string
	var state string

	// Goroutine to poll query status
	go func() {
		defer close(doneCh)

		// Check query status every 2 seconds
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		attempts := 0
		for {
			select {
			case <-queryContext.Done():
				// Context was cancelled or timed out
				log.Printf("Query context done: %v", queryContext.Err())
				return
			case <-ticker.C:
				// Check query status
				attempts++
				status, err := client.GetQueryExecution(&athena.GetQueryExecutionInput{
					QueryExecutionId: aws.String(qid),
				})

				if err != nil {
					errorMsg = fmt.Sprintf("Failed to get query status: %v", err)
					log.Printf(errorMsg)
					return
				}

				state = *status.QueryExecution.Status.State
				log.Printf("Query execution state: %s (attempt %d)", state, attempts)

				if state == "SUCCEEDED" {
					log.Printf("Query succeeded after %d attempts", attempts)
					return
				} else if state == "FAILED" {
					// Get detailed error cause
					stateReason := "Unknown error"
					if status.QueryExecution.Status.StateChangeReason != nil {
						stateReason = *status.QueryExecution.Status.StateChangeReason
					}

					errorMsg = fmt.Sprintf("Athena query failed: %s", stateReason)
					log.Printf("%s\nQuery: %s", errorMsg, query)
					return
				} else if state == "CANCELLED" {
					errorMsg = "Athena query was cancelled"
					log.Printf(errorMsg)
					return
				}
			}
		}
	}()

	// Wait for query completion or timeout
	select {
	case <-doneCh:
		// Query completed (success, failure, or cancelled)
		if errorMsg != "" || state != "SUCCEEDED" {
			if errorMsg == "" {
				errorMsg = fmt.Sprintf("Athena query did not complete successfully. Final state: %s", state)
			}
			return qid, nil, errorMsg, region
		}
	case <-queryContext.Done():
		// Query timed out - force cancellation
		log.Printf("Query timed out after %v. Cancelling query...", queryTimeout)
		_, err := client.StopQueryExecution(&athena.StopQueryExecutionInput{
			QueryExecutionId: aws.String(qid),
		})

		if err != nil {
			log.Printf("Failed to cancel query: %v", err)
		}

		return qid, nil, fmt.Sprintf("Query timed out (%.0f seconds elapsed). Execution aborted.", queryTimeout.Seconds()), region
	}

	// Get results (only on success)
	res, err := client.GetQueryResults(&athena.GetQueryResultsInput{
		QueryExecutionId: aws.String(qid),
		MaxResults:       aws.Int64(20), // Limit to maximum 20 rows
	})

	if err != nil {
		errorMsg = fmt.Sprintf("Failed to get query results: %v", err)
		log.Printf(errorMsg)
		return qid, nil, errorMsg, region
	}

	// Even if additional pagination is needed, use only the first page
	// This prevents prompts like "Continue iteration?"
	if res.NextToken != nil {
		log.Printf("Additional data available, but using only first 20 rows (NextToken: %s...)", (*res.NextToken)[:min(10, len(*res.NextToken))])
	}

	return qid, res.ResultSet.Rows, "", region
}

// preprocessSqlQuery performs preprocessing of SQL queries
func preprocessSqlQuery(query string) string {
	// General query cleaning
	query = strings.TrimSpace(query)

	// Fix database name appropriately (handle cases where table names are not fully qualified)
	if !strings.Contains(query, "amazon_security_lake_glue_db") {
		// When referencing ap-northeast-1 tables but database name is not included
		if strings.Contains(query, "amazon_security_lake_table_ap_northeast_1_waf_2_0") &&
			!strings.Contains(query, "amazon_security_lake_glue_db_ap_northeast_1") {
			query = strings.Replace(
				query,
				"amazon_security_lake_table_ap_northeast_1_waf_2_0",
				"amazon_security_lake_glue_db_ap_northeast_1.amazon_security_lake_table_ap_northeast_1_waf_2_0",
				-1,
			)
		}

		// When referencing us-east-1 tables but database name is not included
		if strings.Contains(query, "amazon_security_lake_table_us_east_1_waf_2_0") &&
			!strings.Contains(query, "amazon_security_lake_glue_db_us_east_1") {
			query = strings.Replace(
				query,
				"amazon_security_lake_table_us_east_1_waf_2_0",
				"amazon_security_lake_glue_db_us_east_1.amazon_security_lake_table_us_east_1_waf_2_0",
				-1,
			)
		}
	}

	// Cast BETWEEN date strings to timestamp type
	betweenRegex := `time_dt\s+BETWEEN\s+'([^']+)'\s+AND\s+'([^']+)'`
	re := regexp.MustCompile(betweenRegex)

	if re.MatchString(query) {
		// Replace entire BETWEEN clause
		query = re.ReplaceAllStringFunc(query, func(match string) string {
			submatches := re.FindStringSubmatch(match)
			if len(submatches) >= 3 {
				date1 := submatches[1]
				date2 := submatches[2]

				// Attempt to convert from JST to UTC (only when timezone is not specified)
				if !strings.Contains(date1, "+") && !strings.Contains(date1, "Z") {
					if t, err := time.Parse("2006-01-02 15:04:05", date1); err == nil {
						// Interpret as JST and convert to UTC (subtract 9 hours)
						utcTime := t.Add(-9 * time.Hour)
						date1 = utcTime.Format("2006-01-02 15:04:05")
						log.Printf("JST to UTC conversion: %s -> %s", submatches[1], date1)
					}
				}

				if !strings.Contains(date2, "+") && !strings.Contains(date2, "Z") {
					if t, err := time.Parse("2006-01-02 15:04:05", date2); err == nil {
						// Interpret as JST and convert to UTC (subtract 9 hours)
						utcTime := t.Add(-9 * time.Hour)
						date2 = utcTime.Format("2006-01-02 15:04:05")
						log.Printf("JST to UTC conversion: %s -> %s", submatches[2], date2)
					}
				}

				// Explicit cast to timestamp
				return fmt.Sprintf("time_dt BETWEEN TIMESTAMP '%s' AND TIMESTAMP '%s'", date1, date2)
			}
			return match
		})
	}

	// Expand simple numeric dates to full format (keep previous implementation as well)
	simpleRegex := `BETWEEN\s+'([^']+)'\s+AND\s+'([^']+)'`
	re = regexp.MustCompile(simpleRegex)
	matches := re.FindAllStringSubmatch(query, -1)

	for _, match := range matches {
		if len(match) == 3 {
			date1 := match[1]
			date2 := match[2]

			// For simple year-only cases (e.g., '2020')
			if len(date1) == 4 && isNumeric(date1) {
				newDate1 := date1 + "-01-01 00:00:00"
				query = strings.Replace(query, "'"+date1+"'", "TIMESTAMP '"+newDate1+"'", 1)
			}

			if len(date2) == 4 && isNumeric(date2) {
				newDate2 := date2 + "-12-31 23:59:59"
				query = strings.Replace(query, "'"+date2+"'", "TIMESTAMP '"+newDate2+"'", 1)
			}
		}
	}

	log.Printf("Preprocessed query: %s", query)
	return query
}

// formatAthenaResults formats Athena query results
func formatAthenaResults(rows []*athena.Row) string {
	if len(rows) == 0 {
		return "No results found"
	}

	// Get header row (conditionally include _col columns as well)
	var headers []string
	var colIndices []int    // Hold indices of columns to display
	var colHeaders []string // For _col format columns

	for i, data := range rows[0].Data {
		if data.VarCharValue != nil {
			colName := *data.VarCharValue
			// Prioritize normal columns
			if !strings.HasPrefix(colName, "_col") {
				headers = append(headers, colName)
				colIndices = append(colIndices, i)
			} else {
				// Save _col format columns for potential later use
				colHeaders = append(colHeaders, colName)
				// Don't add to colIndices
			}
		}
	}

	// If there are no normal columns, use _col format columns as well
	if len(headers) == 0 && len(colHeaders) > 0 {
		log.Printf("No normal columns found, using _col format columns")
		// _col0 gets special treatment (usually excluded as it's a row number)
		for i, data := range rows[0].Data {
			if data.VarCharValue != nil {
				colName := *data.VarCharValue
				if colName != "_col0" && strings.HasPrefix(colName, "_col") {
					headers = append(headers, colName)
					colIndices = append(colIndices, i)
				}
			}
		}
	}

	// If there are still no columns to display
	if len(headers) == 0 {
		// As a last resort, display all columns including _col0
		for i, data := range rows[0].Data {
			if data.VarCharValue != nil {
				headers = append(headers, *data.VarCharValue)
				colIndices = append(colIndices, i)
			}
		}

		// If there are still no columns
		if len(headers) == 0 {
			return "No displayable columns found"
		}
	}

	// Format results
	var sb strings.Builder

	// Calculate maximum width of columns
	colWidths := make([]int, len(headers))
	for i, header := range headers {
		colWidths[i] = len(header)
	}

	// Scan each data row to update maximum width
	maxRows := len(rows)
	if maxRows > 20 {
		maxRows = 20
	}

	for i := 1; i < maxRows; i++ {
		if i >= len(rows) {
			break
		}

		for colIndex, colIdx := range colIndices {
			if colIdx < len(rows[i].Data) {
				data := rows[i].Data[colIdx]
				if data.VarCharValue != nil {
					valueLen := len(*data.VarCharValue)
					if valueLen > colWidths[colIndex] {
						colWidths[colIndex] = valueLen
					}
				}
			}
		}
	}

	// Add header row
	sb.WriteString("```\n")

	// Header row
	for i, header := range headers {
		format := fmt.Sprintf("%%-%ds", colWidths[i]+2) // +2 for spacing
		sb.WriteString(fmt.Sprintf(format, header))
	}
	sb.WriteString("\n")

	// Separator line
	for _, width := range colWidths {
		sb.WriteString(strings.Repeat("-", width+2))
	}
	sb.WriteString("\n")

	// Add data rows
	for i := 1; i < maxRows; i++ { // Skip header row
		// Check index range
		if i >= len(rows) {
			break // If there are fewer rows than expected
		}

		for colIndex, colIdx := range colIndices {
			var value string
			if colIdx < len(rows[i].Data) {
				data := rows[i].Data[colIdx]
				if data.VarCharValue != nil {
					value = *data.VarCharValue
				} else {
					value = "NULL"
				}
			} else {
				// When column index is out of range
				value = "N/A"
			}

			// Format and add each column
			format := fmt.Sprintf("%%-%ds", colWidths[colIndex]+2) // +2 for spacing
			sb.WriteString(fmt.Sprintf(format, value))
		}
		sb.WriteString("\n")
	}

	// Note when there are many records
	if len(rows) > 20 {
		sb.WriteString("...(Results limited to 20 rows)\n")
	}

	sb.WriteString("```\n")
	return sb.String()
}

// getAthenaClient function: generates Athena client based on region
func getAthenaClient(region string) *athena.Athena {
	log.Printf("Creating Athena client (region: %s)", region)
	return athena.New(session.Must(session.NewSession(&aws.Config{
		Region: aws.String(region),
	})))
}

// formatResultsForAnalysis formats results for analysis
func formatResultsForAnalysis(rows []*athena.Row) string {
	if len(rows) == 0 {
		return "No data available"
	}

	// Limit maximum rows (too large may reach token limit)
	maxRows := min(len(rows), 50)

	var sb strings.Builder

	// Get header row (conditionally include _col columns as well)
	var headers []string
	var colIndices []int    // Hold indices of columns to display
	var colHeaders []string // For _col format columns

	for i, data := range rows[0].Data {
		if data.VarCharValue != nil {
			colName := *data.VarCharValue
			// Prioritize normal columns
			if !strings.HasPrefix(colName, "_col") {
				headers = append(headers, colName)
				colIndices = append(colIndices, i)
			} else {
				// Save _col format columns for potential later use
				colHeaders = append(colHeaders, colName)
				// Don't add to colIndices
			}
		}
	}

	// If there are no normal columns, use _col format columns as well
	if len(headers) == 0 && len(colHeaders) > 0 {
		log.Printf("For analysis: No normal columns found, using _col format columns")
		// _col0 gets special treatment (usually excluded as it's a row number)
		for i, data := range rows[0].Data {
			if data.VarCharValue != nil {
				colName := *data.VarCharValue
				if colName != "_col0" && strings.HasPrefix(colName, "_col") {
					headers = append(headers, colName)
					colIndices = append(colIndices, i)
				}
			}
		}
	}

	// If there are still no columns to display
	if len(headers) == 0 {
		// As a last resort, display all columns including _col0
		for i, data := range rows[0].Data {
			if data.VarCharValue != nil {
				headers = append(headers, *data.VarCharValue)
				colIndices = append(colIndices, i)
			}
		}

		// If there are still no columns
		if len(headers) == 0 {
			return "No displayable columns found"
		}
	}

	// Add header row
	// Calculate maximum width of columns
	colWidths := make([]int, len(headers))
	for i, header := range headers {
		colWidths[i] = len(header)
	}

	// Scan each data row to update maximum width
	for i := 1; i < maxRows; i++ {
		if i >= len(rows) {
			break
		}

		for colIndex, colIdx := range colIndices {
			if colIdx < len(rows[i].Data) {
				data := rows[i].Data[colIdx]
				if data.VarCharValue != nil {
					valueLen := len(*data.VarCharValue)
					if valueLen > colWidths[colIndex] {
						colWidths[colIndex] = valueLen
					}
				}
			}
		}
	}

	// Header row
	for i, header := range headers {
		format := fmt.Sprintf("%%-%ds", colWidths[i]+2) // +2 for spacing
		sb.WriteString(fmt.Sprintf(format, header))
	}
	sb.WriteString("\n")

	// Separator line
	for _, width := range colWidths {
		sb.WriteString(strings.Repeat("-", width+2))
	}
	sb.WriteString("\n")

	// Add data rows
	for i := 1; i < maxRows; i++ {
		// Check index range
		if i >= len(rows) {
			break // If there are fewer rows than expected
		}

		for colIndex, colIdx := range colIndices {
			var value string
			if colIdx < len(rows[i].Data) {
				data := rows[i].Data[colIdx]
				if data.VarCharValue != nil {
					value = *data.VarCharValue
				} else {
					value = "NULL"
				}
			} else {
				// When column index is out of range
				value = "N/A"
			}

			// Format and add each column
			format := fmt.Sprintf("%%-%ds", colWidths[colIndex]+2) // +2 for spacing
			sb.WriteString(fmt.Sprintf(format, value))
		}
		sb.WriteString("\n")
	}

	// Note when rows are limited
	if len(rows) > maxRows {
		sb.WriteString(fmt.Sprintf("\n... (%d more rows not displayed)", len(rows)-maxRows))
	}

	return sb.String()
}

// extractDateRange extracts date range from query
func extractDateRange(query string) string {
	// Regular expression to detect BETWEEN clause
	re := regexp.MustCompile(`time_dt\s+BETWEEN\s+TIMESTAMP\s+'([^']+)'\s+AND\s+TIMESTAMP\s+'([^']+)'`)
	matches := re.FindStringSubmatch(query)

	if len(matches) >= 3 {
		return fmt.Sprintf("from %s to %s", matches[1], matches[2])
	}

	return "unknown" // When date range cannot be determined
}
