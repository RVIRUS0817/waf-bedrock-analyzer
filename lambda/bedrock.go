package main

import (
	"bytes"
	"encoding/json"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/athena"
	"github.com/aws/aws-sdk-go/service/bedrockruntime"
)

// callBedrock calls the Bedrock service to generate SQL from a prompt
func callBedrock(prompt string) string {
	body := map[string]interface{}{
		"anthropic_version": "bedrock-2023-05-31",
		"max_tokens":        1000,
		"messages": []map[string]interface{}{
			{
				"role": "user",
				"content": []map[string]string{
					{
						"type": "text",
						"text": prompt,
					},
				},
			},
		},
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		log.Fatalf("Failed to marshal body: %v", err)
	}

	input := &bedrockruntime.InvokeModelInput{
		ModelId:     aws.String("apac.anthropic.claude-3-sonnet-20240229-v1:0"),
		ContentType: awsString("application/json"),
		Accept:      awsString("application/json"),
		Body:        jsonBody,
	}

	output, err := bedrockClient.InvokeModel(input)
	if err != nil {
		log.Fatalf("InvokeModel failed: %v", err)
	}

	buf := new(bytes.Buffer)
	if _, err := buf.Write(output.Body); err != nil {
		log.Fatalf("Failed to read Bedrock response: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		log.Fatalf("Failed to parse response JSON: %v", err)
	}

	// Extract text from Claude's response structure (content[])
	contentList, ok := parsed["content"].([]interface{})
	if !ok || len(contentList) == 0 {
		log.Fatalf("Invalid content structure in Bedrock response")
	}

	first := contentList[0].(map[string]interface{})
	text, ok := first["text"].(string)
	if !ok {
		log.Fatalf("No text field in Bedrock content")
	}

	return text
}

// buildPrompt constructs a prompt for generating Athena SQL queries from user text
func buildPrompt(userText string) string {
	return `Generate an Athena SQL query based on the following user request.

### Table Information:
- Table: amazon_security_lake_glue_db_ap_northeast_1.amazon_security_lake_table_ap_northeast_1_waf_2_0 (WAF test-api table)
- Table: amazon_security_lake_glue_db_us_east_1.amazon_security_lake_table_us_east_1_waf_2_0 (WAF test-frontend table)

### Main Columns:
- time_dt (timestamp) - Event timestamp
- accountid (string) - AWS Account ID
- metadata.product.feature.uid (string) - WAF identifier
- http_request.url.hostname (string) - Request hostname
- src_endpoint.ip (string) - Source IP address
- unmapped['action'] - WAF action (ALLOW, BLOCK, COUNT)

### SQL Examples:

-- Example 1: Count requests by action type
SELECT 
    unmapped['action'] AS action_type,
    COUNT(*) AS request_count
FROM amazon_security_lake_glue_db_ap_northeast_1.amazon_security_lake_table_ap_northeast_1_waf_2_0
WHERE 
    accountid = 'xxxxxxxxxxxxxx'
    AND time_dt >= current_date - INTERVAL '1' DAY
    AND src_endpoint.ip NOT IN ('xx.xx.xx.xx', 'xx.xx.xx.xx')
GROUP BY unmapped['action']
ORDER BY request_count DESC
LIMIT 5;

-- Example 2: Top source IPs
SELECT 
    src_endpoint.ip AS source_ip,
    COUNT(*) AS request_count
FROM amazon_security_lake_glue_db_ap_northeast_1.amazon_security_lake_table_ap_northeast_1_waf_2_0
WHERE 
    accountid = 'xxxxxxxxxxxxxx'
    AND time_dt >= current_date - INTERVAL '1' DAY
    AND src_endpoint.ip NOT IN ('xx.xx.xx.xx', 'xx.xx.xx.xx')
GROUP BY src_endpoint.ip
ORDER BY request_count DESC
LIMIT 5;

-- Example 3: Blocked requests analysis
SELECT 
    http_request.url.hostname AS hostname,
    COUNT(*) AS block_count
FROM amazon_security_lake_glue_db_ap_northeast_1.amazon_security_lake_table_ap_northeast_1_waf_2_0
WHERE 
    accountid = 'xxxxxxxxxxxxxx'
    AND unmapped['action'] = 'BLOCK'
    AND time_dt >= current_date - INTERVAL '1' DAY
    AND src_endpoint.ip NOT IN ('xx.xx.xx.xx', 'xx.xx.xx.xx')
GROUP BY http_request.url.hostname
ORDER BY block_count DESC
LIMIT 5;

### User Request: ` + userText + `

Please generate only the SQL query without any explanation.`
}

// analyzeResults analyzes the results of an Athena query and provides a summary
func analyzeResults(query string, results []*athena.Row, userText string) string {
	if len(results) <= 1 { // Header only, or no data
		return "No data found. Please try different search criteria."
	}

	// Create analysis prompt
	analysisPrompt := "[ANALYSIS PROMPT MASKED]"

	// Call Bedrock for analysis
	analysisResult := callBedrock(analysisPrompt)
	return analysisResult
}
