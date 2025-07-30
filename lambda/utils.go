package main

import (
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
)

// awsString converts string type to *string type for AWS SDK
func awsString(s string) *string {
	return &s
}

// isNumeric checks if a string contains only numbers
func isNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

// min function (for Go < 1.21)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// response generates API Gateway response
func response(code int, body string) events.APIGatewayProxyResponse {
	return events.APIGatewayProxyResponse{
		StatusCode: code,
		Body:       body,
		Headers: map[string]string{
			"Content-Type": "application/json",
			"X-Processed":  "true", // Header indicating processing is complete
		},
	}
}

// getQueryRegion detects region from SQL query
func getQueryRegion(query string) string {
	// Default is ap-northeast-1
	defaultRegion := "ap-northeast-1"

	// Log output
	log.Printf("Query analysis for region detection: %s", query)

	// When query explicitly references us-east-1 tables
	if strings.Contains(query, "amazon_security_lake_glue_db_us_east_1") ||
		strings.Contains(query, "amazon_security_lake_table_us_east_1") ||
		strings.Contains(query, "waf_2_0_us_east_1") {
		log.Printf("Region detection: us-east-1 (based on table reference)")
		return "us-east-1"
	}

	// When referencing frontend WAF (us-east-1)
	if strings.Contains(query, "frontend") {
		log.Printf("Region detection: us-east-1 (based on frontend-related keywords)")
		return "us-east-1"
	}

	// GLOBAL WEBACL references are us-east-1
	if strings.Contains(query, "global/webacl") {
		log.Printf("Region detection: us-east-1 (based on global/webacl)")
		return "us-east-1"
	}

	log.Printf("Region detection: %s (default)", defaultRegion)
	return defaultRegion
}

// containsFrontendKeywords determines if user text is related to frontend WAF
func containsFrontendKeywords(text string) bool {
	// Convert to lowercase for search
	lowerText := strings.ToLower(text)

	// List of frontend-related keywords
	frontendKeywords := []string{
		"frontend", "front-end", "front end",
		"global",
		"us-east-1", "us east 1",
	}

	// Return true if any keyword is found
	for _, keyword := range frontendKeywords {
		if strings.Contains(lowerText, keyword) {
			log.Printf("Detected frontend-related keyword '%s'", keyword)
			return true
		}
	}

	return false
}

// Cache to hold processed event IDs (LRU cache would be better)
var processedEvents = make(map[string]bool)

// Holds executed queries and their timestamps (prevents duplicate execution of same query in short time)
var recentQueries = make(map[string]time.Time)
