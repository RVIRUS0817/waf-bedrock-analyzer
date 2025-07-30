package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// Hold hashes of recently sent Slack messages
var recentSlackMessages = make(map[string]time.Time)

// postToSlack sends a message to a Slack channel
func postToSlack(channel, msg string) error {
	// Message duplication check (don't send identical or similar messages to the same channel)
	// Generate message hash (improved for more reliable duplicate detection)
	// Basic format: "channel + characteristic part of message"
	contentSignature := msg

	// Extract characteristic part if message is long
	if len(msg) > 50 {
		// Extract data part from logs
		if strings.Contains(msg, "*result:*") {
			// Get result count part (becomes important characteristic)
			resultParts := strings.Split(msg, "*result:*")
			if len(resultParts) > 1 {
				countPart := strings.Split(resultParts[1], "\n")[0]
				contentSignature = fmt.Sprintf("WAF result:%s", countPart)
			}
		}
	}

	msgHash := fmt.Sprintf("%s:%s", channel, contentSignature)
	log.Printf("Message signature: %s", msgHash)

	// Check if identical or similar message was sent within the last 3 minutes
	// Use longer time to prevent duplicate sending
	if lastTime, exists := recentSlackMessages[msgHash]; exists {
		timeSince := time.Since(lastTime)
		if timeSince < 3*time.Minute {
			log.Printf("Suppressing duplicate Slack message: channel %s (sent %.2f seconds ago)",
				channel, timeSince.Seconds())
			return nil
		}
	}

	// Record in send history
	recentSlackMessages[msgHash] = time.Now()

	// Size limit and cleanup of old entries in recentSlackMessages
	if len(recentSlackMessages) > 50 {
		// Delete entries older than 10 minutes (keep cache clean)
		now := time.Now()
		cleanedCount := 0
		for k, t := range recentSlackMessages {
			if now.Sub(t) > 10*time.Minute {
				delete(recentSlackMessages, k)
				cleanedCount++
			}
		}
		log.Printf("Cleaned up Slack message cache: %d entries deleted (%d remaining)",
			cleanedCount, len(recentSlackMessages))
	}

	// Token check
	if slackToken == "" {
		errMsg := "Slack token is empty. Unable to send message to Slack."
		log.Printf(errMsg)
		return fmt.Errorf(errMsg)
	}

	slackURL := "https://slack.com/api/chat.postMessage"

	// Perform proper escape processing with JSON encoding
	reqBody, err := json.Marshal(map[string]string{
		"channel": channel,
		"text":    msg,
	})
	if err != nil {
		log.Printf("Slack JSON encoding error: %v", err)
		return err
	}

	req, err := http.NewRequest("POST", slackURL, bytes.NewBuffer(reqBody))
	if err != nil {
		log.Printf("Slack request creation error: %v", err)
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+slackToken)

	// Debug information (already confirmed token is not empty)
	tokenPreview := "****"
	if len(slackToken) >= 4 {
		tokenPreview = slackToken[:4] + "..."
	}
	log.Printf("Sending to Slack - Channel: %s, Token: %s", channel, tokenPreview)

	// Convert query to plain text (avoid outputting JSON with braces and special characters to logs)
	plainText := strings.Replace(string(reqBody), "\\", "", -1)
	plainText = strings.Replace(plainText, "\n", " ", -1)
	// Shorten if too long
	if len(plainText) > 100 {
		plainText = plainText[:97] + "..."
	}
	log.Printf("Message content preview: %s", plainText)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Slack request error: %v", err)
		return err
	}
	defer resp.Body.Close()

	// Read response body to check details
	var respBody []byte
	respBody, err = io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read Slack response body: %v", err)
		return err
	}

	// Output response to logs (for diagnostics)
	log.Printf("Slack API response - Status: %d, Body length: %d", resp.StatusCode, len(respBody))

	// Parse response from Slack
	var slackResp map[string]interface{}
	if err := json.Unmarshal(respBody, &slackResp); err != nil {
		log.Printf("Failed to parse Slack response: %v", err)
		return err
	}

	// Check if successful
	if success, ok := slackResp["ok"].(bool); ok && success {
		log.Printf("Successfully sent Slack message (signature: %s)", msgHash)
		return nil
	} else {
		// Get error details
		errMsg := "Unknown error"
		if slackErr, ok := slackResp["error"].(string); ok {
			errMsg = slackErr
		}
		log.Printf("Slack API error: %s (signature: %s)", errMsg, msgHash)
		return fmt.Errorf("Slack API error: %s", errMsg)
	}
}

// More detailed Slack event structure
type SlackEventWrapper struct {
	Token    string `json:"token"`
	TeamID   string `json:"team_id"`
	APIAppID string `json:"api_app_id"`
	Event    struct {
		Type    string `json:"type"`
		Text    string `json:"text"`
		User    string `json:"user"`
		Channel string `json:"channel"`
		EventTS string `json:"event_ts"`
	} `json:"event"`
	Type           string `json:"type"`
	EventID        string `json:"event_id"`
	EventTime      int    `json:"event_time"`
	Challenge      string `json:"challenge"`
	AuthorizedUser string `json:"authorized_user"`
}
