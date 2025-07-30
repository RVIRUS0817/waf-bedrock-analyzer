# waf-bedrock-analyzer

Workflow for WAF Data Analysis and Response Using Amazon Bedrock and Go.

![Image](https://github.com/user-attachments/assets/983ccf20-ae5e-46b0-af9d-94e9bbd8e2b5)

- Slack
- Amazon API Gateway
- AWS Lambda(Go)
  - env
    - SlackBotToken
- Amazon Athena
- Amazon Bedrock
- Amazon S3

## Lambda Deploy

Please customize the prompt in bedrock.go.

- build

```bash
$ cd lambda
$ GOOS=linux GOARCH=arm64 go build -o ../files/BedrockSlackHandler/bootstrap
```

## How to Ask Questions in slack Channel


- Analyze requests from a specific IP

@AI For the test account’s API, tell me the source IP address with the highest number of requests in the past 3 days and the corresponding request count.


- Analyze blocked requests by time of day

@AI For the test account’s frontend WAF, please aggregate the blocked requests by hour for last week.

- Check triggered rule activity

@AI For the test account’s API WAF, tell me which rule test was triggered the most in the past 24 hours and how many times it was triggered.
