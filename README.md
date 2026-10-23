# Cybersecurity Incident Analysis using SQL

## Project Overview
This project analyzes cybersecurity incident data using SQL to identify incident patterns, examine login activity, and explore potential security risks.

The analysis focuses on incident severity, incident types, industry and country distributions, failed login attempts, and user login behavior.

## Objectives
- Analyze the distribution of cybersecurity incidents by severity and type.
- Identify incident categories with the highest counts.
- Examine failed and successful login attempts.
- Identify users with repeated failed login attempts.
- Analyze failed login rates and compare login behavior across users.
- Explore incident patterns across industries and countries.

## Tools & Technologies
- SQL
- PostgreSQL
- GitHub

## Dataset
The project uses CSV datasets stored in the `csv_files` folder.

The datasets cover security incidents, login logs, users, organizations, systems, network events, and incident-system relationships.

## Key Analysis Areas
1. Incident severity distribution
2. Incident type distribution
3. Malware incidents and severity
4. Incident distribution by industry and country
5. Successful and failed login activity
6. Users with the highest number of failed login attempts
7. Users with repeated failed attempts and successful logins
8. IP addresses associated with failed login attempts
9. High- and critical-severity incidents by industry
10. User login behavior and failed login rates

## Key Findings
- Critical incidents represented **28%** of all 500 recorded incidents.
- Critical and High severity incidents together represented **52%** of recorded incidents.
- Malware was the most common incident type, accounting for **37%** of incidents.
- Retail had the highest incident count among the industries analyzed.
- The United States had the highest incident count among the countries analyzed.
- Failed login attempts accounted for approximately **49.33%** of all recorded login attempts.
- Four users recorded the highest number of failed login attempts, with **8 attempts each**.
- A total of **73 user accounts** had at least five failed login attempts and at least one successful login.

## Limitations
- The findings describe patterns in the available dataset and do not establish that any user or IP address was malicious.
- Higher incident counts do not necessarily indicate weaker security, as organization size and other factors were not evaluated.
- Further investigation and additional context would be required before drawing operational security conclusions.

## Repository Structure
- `csv_files/` — Dataset CSV files
- `my_solutions/` — SQL analysis queries
- `README.md` — Project documentation

## Conclusion
This project demonstrates the use of SQL for data aggregation, filtering, joins, common table expressions (CTEs), window functions, ranking, and percentage calculations to analyze cybersecurity-related data.

The analysis helps highlight patterns that could be prioritized for further investigation.


