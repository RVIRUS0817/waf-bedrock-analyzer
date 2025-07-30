package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/bedrockruntime"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

var (
	bedrockClient = bedrockruntime.New(session.Must(session.NewSession(&aws.Config{
		Region: aws.String("ap-northeast-1"),
	})))
	secretsClient = secretsmanager.New(session.Must(session.NewSession()))

	slackToken      string
	athenaDB        = os.Getenv("ATHENA_DATABASE")
	athenaOutput    = os.Getenv("ATHENA_OUTPUT_BUCKET")
	athenaWorkgroup = os.Getenv("ATHENA_WORKGROUP")
	// Display control by environment variable
	showSqlInSlack     = os.Getenv("SHOW_SQL_IN_SLACK") != "false"      // Display by default
	showQueryIdInSlack = os.Getenv("SHOW_QUERY_ID_IN_SLACK") != "false" // Display by default
)

func init() {
	secretID := os.Getenv("SLACK_BOT_TOKEN_SECRET_NAME")
	if secretID == "" {
		log.Printf("Warning: SLACK_BOT_TOKEN_SECRET_NAME environment variable is not set")
		return
	}

	log.Printf("Attempting to get secret: %s", secretID)

	result, err := secretsClient.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretID),
	})
	if err != nil {
		log.Printf("Failed to get secret value: %v", err)
		return
	}

	if result.SecretString == nil {
		log.Printf("Secret value is nil")
		return
	}

	// Get secret string
	secretString := *result.SecretString
	log.Printf("Retrieved secret string (length: %d)", len(secretString))

	// Use as is if plain text
	if !strings.HasPrefix(secretString, "{") {
		slackToken = secretString
		log.Printf("Using plain text secret as token")
		return
	}

	// Parse as JSON
	var secretMap map[string]interface{}
	if err := json.Unmarshal([]byte(secretString), &secretMap); err != nil {
		// If not JSON, use entire string as token
		log.Printf("Secret is not in JSON format, using as plain token")
		slackToken = secretString
		return
	}

	// If parsed as JSON, look for token
	if token, ok := secretMap["token"].(string); ok && token != "" {
		slackToken = token
	} else if token, ok := secretMap["slack_token"].(string); ok && token != "" {
		slackToken = token
	} else if token, ok := secretMap["SLACK_TOKEN"].(string); ok && token != "" {
		slackToken = token
	} else {
		// If key not found or value is empty
		log.Printf("Token not found in secret JSON, using entire secret as token")
		slackToken = secretString
	}

	if slackToken == "DUMMY" || slackToken == "" {
		log.Printf("Retrieved token is empty or DUMMY value")
		return
	}

	log.Printf("Successfully retrieved Slack token (length: %d)", len(slackToken))
}

func handler(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	log.Printf("Received request: %s", req.Body)

	if retryNum := req.Headers["X-Slack-Retry-Num"]; retryNum != "" {
		log.Printf("Slack retry detected: %s (reason: %s)", retryNum, req.Headers["X-Slack-Retry-Reason"])
		return response(200, "retry ignored"), nil
	}

	// Log environment variable settings
	log.Printf("Env config - SHOW_SQL_IN_SLACK: %v, showSqlInSlack: %v",
		os.Getenv("SHOW_SQL_IN_SLACK"), showSqlInSlack)
	log.Printf("Env config - SHOW_QUERY_ID_IN_SLACK: %v, showQueryIdInSlack: %v",
		os.Getenv("SHOW_QUERY_ID_IN_SLACK"), showQueryIdInSlack)

	// Parse and respond to challenge request
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(req.Body), &payload); err != nil {
		log.Printf("Failed to parse payload: %v", err)
		return response(400, "invalid request"), nil
	}

	// Respond to Slack URL verification challenge
	if challenge, ok := payload["challenge"].(string); ok {
		log.Printf("Responding to Slack URL verification challenge")
		return events.APIGatewayProxyResponse{
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "text/plain"},
			Body:       challenge,
		}, nil
	}

	// Parse event details
	var wrapper SlackEventWrapper
	if err := json.Unmarshal([]byte(req.Body), &wrapper); err != nil {
		log.Printf("Failed to parse SlackEventWrapper: %v", err)
		return response(400, "invalid event format"), nil
	}

	// Check request type - only event_callback is supported
	if wrapper.Type != "event_callback" {
		log.Printf("Ignoring non-event callback request type: %s", wrapper.Type)
		return response(200, "ignored"), nil
	}

	// Check event type - ignore non-message events
	if wrapper.Event.Type != "message" && wrapper.Event.Type != "app_mention" {
		log.Printf("Ignoring non-message event type: %s", wrapper.Event.Type)
		return response(200, "ignored non-message event"), nil
	}

	// Ignore bot's own messages (prevent reply loop)
	if wrapper.Event.User == "U08N7NYBPAL" {
		log.Printf("Ignoring bot's own message")
		return response(200, "ignored bot message"), nil
	}

	// Check for duplicate events
	if wrapper.EventID != "" {
		// Stricter check: combine event ID and request body hash
		eventKey := wrapper.EventID + "_" + wrapper.Event.Text + "_" + wrapper.Event.Channel

		if _, exists := processedEvents[eventKey]; exists {
			log.Printf("Ignoring duplicate event with key: %s (ID=%s, Text='%s')",
				eventKey, wrapper.EventID, wrapper.Event.Text)
			return response(200, "duplicate event"), nil
		}

		// Mark as processed
		processedEvents[eventKey] = true
		log.Printf("Marking event as processed: key=%s (ID=%s)", eventKey, wrapper.EventID)

		// Limit cache size (max 100)
		if len(processedEvents) > 100 {
			// Simple cleaning (should use LRU cache in production)
			log.Printf("Clearing event cache (size=%d)", len(processedEvents))
			processedEvents = make(map[string]bool)
			processedEvents[eventKey] = true
		}
	}

	// Output additional event info to log (for debugging)
	log.Printf("Processing event: ID=%s, Type=%s, User=%s, Text='%s'",
		wrapper.EventID, wrapper.Event.Type, wrapper.Event.User, wrapper.Event.Text)

	// Get text and remove bot mention
	text := strings.TrimSpace(wrapper.Event.Text)
	text = strings.ReplaceAll(text, "<@U08N7NYBPAL>", "")
	text = strings.TrimSpace(text)

	// Ignore empty or too short messages
	if text == "" || len(text) < 3 {
		log.Printf("Ignoring empty or too short message")
		return response(200, "ignored empty message"), nil
	}

	// Check for duplicate query execution in short time (within 5 seconds)
	queryKey := wrapper.Event.Channel + ":" + text
	if lastTime, exists := recentQueries[queryKey]; exists {
		timeSince := time.Since(lastTime)
		if timeSince < 5*time.Second {
			log.Printf("Ignoring duplicate query '%s' executed %.2f seconds ago",
				text, timeSince.Seconds())
			return response(200, "duplicate query ignored"), nil
		}
	}
	// Record current time
	recentQueries[queryKey] = time.Now()

	// Limit recentQueries size
	if len(recentQueries) > 200 {
		// Delete old entries
		log.Printf("Cleaning up recentQueries cache (size=%d)", len(recentQueries))
		now := time.Now()
		for k, t := range recentQueries {
			if now.Sub(t) > 10*time.Minute {
				delete(recentQueries, k)
			}
		}
		// If still too large, clear all
		if len(recentQueries) > 150 {
			recentQueries = make(map[string]time.Time)
			recentQueries[queryKey] = time.Now()
		}
	}

	log.Printf("Processing query: %s", text)

	// Prompt generation
	prompt := buildPrompt(text)

	// Call Bedrock to generate SQL
	sql := callBedrock(prompt)
	log.Printf("Generated SQL: %s", sql)

	// Detect region from query
	queryRegion := getQueryRegion(sql)

	// Execute Athena query
	qid, rows, errMsg, _ := runAthenaQuery(ctx, sql)

	// Generate console URL
	consoleUrl := fmt.Sprintf("https://ap-northeast-1.console.aws.amazon.com/athena/home?region=ap-northeast-1#/query-editor/history/%s", qid)
	// Change URL for US-EAST region
	if queryRegion == "us-east-1" {
		consoleUrl = fmt.Sprintf("https://us-east-1.console.aws.amazon.com/athena/home?region=us-east-1#/query-editor/history/%s", qid)
		log.Printf("Adjusted console URL for us-east-1 region: %s", consoleUrl)
	}

	// Error handling
	if errMsg != "" {
		detailedError := fmt.Sprintf("Query failed (region: %s): %s\n\n", queryRegion, errMsg)

		// Always show SQL for debugging on error
		detailedError += fmt.Sprintf("Executed SQL:\n```\n%s\n```\n\n", sql)
		detailedError += fmt.Sprintf("Athena Console: %s", consoleUrl)

		log.Printf("Query failed: %s", detailedError)
		postToSlack(wrapper.Event.Channel, detailedError)
		return response(200, "error reported to slack"), nil
	}

	// Output on success
	var resultMessage strings.Builder
	resultMessage.WriteString(fmt.Sprintf("*WAF Log Search Result*\n\n"))

	// Decide whether to show SQL based on environment variable
	if showSqlInSlack {
		// Shorten prompt if too long
		displayText := text
		if len(text) > 100 {
			displayText = text[:97] + "..."
		}
		resultMessage.WriteString(fmt.Sprintf("*Input Prompt:*\n```\n%s\n```\n\n", displayText))
		resultMessage.WriteString(fmt.Sprintf("*Executed Query:*\n```\n%s\n```\n\n", sql))
	}

	// Row count info
	resultMessage.WriteString(fmt.Sprintf("*Result:* %d rows\n", len(rows)-1)) // Exclude header row
	if showQueryIdInSlack {
		resultMessage.WriteString(fmt.Sprintf("*Athena QueryID:* `%s`\n", qid))
		resultMessage.WriteString(fmt.Sprintf("*Console URL:* %s\n\n", consoleUrl))
	}

	// Add result table (using formatAthenaResults)
	if len(rows) > 1 { // At least one row (header exists)
		resultMessage.WriteString("*Result Data:*\n")
		resultMessage.WriteString(formatAthenaResults(rows))
	} else {
		resultMessage.WriteString("*Result Data:* No data available")
	}

	// Add analysis result
	analysisResult := analyzeResults(sql, rows, text)
	resultMessage.WriteString(fmt.Sprintf("\n*Analysis Result:*\n%s", analysisResult))

	// Log region info
	log.Printf("Starting to send to Slack (region: %s, message size: %d)", queryRegion, len(resultMessage.String()))

	// Send to Slack
	err := postToSlack(wrapper.Event.Channel, resultMessage.String())
	if err != nil {
		log.Printf("Slack send error: %v", err)
	} else {
		log.Printf("Successfully sent to Slack (region: %s)", queryRegion)
	}
	return response(200, "ok"), nil
}

func main() {
	lambda.Start(handler)
}
