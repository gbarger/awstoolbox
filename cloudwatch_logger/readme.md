# AWS CloudWatch Logger tool

The purpose of this tool is to be a simple logger to make it easy to write logs
to CloudWatch with log levels that are easily configured and have a namespace
set as a singleton so it doesn't change across modules if you use it in multiple
files and finally let you save values to the logs to make it easy to create 
custom CloudWatch metrics.

## Usage
1. If you want external configuraiton like using a lambda environment variables, 
then you should configure those values externally.
2. Instatiate your logger with whatever namespace you want.
3. Write messages using the appropriate log type. If the type you're logging
is above the configured log threshold then it will print the output.

## Example in lambda function
`
import logger

log = logger.Logger("my_code_namespace", log_level=os.environ["log_level"])
log.debug("my debug message")
log.info("my info message", metrics={"myMetric":0, "myMetric2":"value"})
log.warning("my warning message")
log.error("received an error", metrics={"errorMessage":"error message encountered"})
log.critical("hit critical error, sending emergency alert.", metrics={"critErrorMessage":"critical error message encountered"})
`