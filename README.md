# Cybersecurity Incident Analysis Using SQL

## Project Overview

This project analyzes cybersecurity incident data using SQL to identify incident patterns, examine login activity, and explore potential security risks.

The analysis covers incident severity and types, industry and country distributions, login behavior, network events, system involvement in incidents, monthly incident frequency, and organization-level security indicators.

## Objectives

- Analyze the distribution of cybersecurity incidents by severity and type.
- Identify the most frequently recorded incident categories.
- Examine incident patterns across industries and countries.
- Analyze successful and failed login attempts.
- Identify users with high numbers of failed login attempts and unusual login patterns.
- Investigate IP addresses associated with repeated failed and successful logins.
- Identify systems generating the highest numbers of network events and critical alerts.
- Analyze the involvement of systems in recorded security incidents.
- Examine monthly incident frequency.
- Compare organizations by total incidents and High/Critical incident counts.

## Tools & Technologies

- SQL
- PostgreSQL
- GitHub

## Dataset

The project uses CSV datasets stored in the `csv_files/` folder.

The datasets cover:

- Security incidents
- Login logs
- Users
- Organizations
- Systems
- Network events
- Incident-system relationships

The data was imported into PostgreSQL for analysis.

## Key Analysis Areas

1. Incident severity distribution
2. Incident type distribution
3. Malware incident frequency and severity
4. Incident distribution by industry and country
5. Organization count and operating system distribution
6. Users with the highest number of failed login attempts
7. Users with repeated failed attempts and successful logins
8. IP addresses associated with repeated failed and successful login attempts
9. User login activity and failure rates
10. Systems generating the highest numbers of network events
11. Organizations with the highest numbers of security incidents
12. Systems involved in the highest numbers of incidents
13. Systems generating the most Critical alerts
14. Industries with the highest numbers of security incidents
15. Monthly security incident frequency
16. Organizations ranked by High/Critical incident counts

## Key Findings

### Incident Analysis

- The dataset contains **500 recorded security incidents**.
- Critical incidents represented **28%** of all recorded incidents.
- Critical and High severity incidents together represented **52%** of recorded incidents.
- Malware was the most common incident type, accounting for **37%** of incidents.
- Retail recorded the highest number of incidents among the industries analyzed.
- The United States recorded the highest number of incidents among the countries analyzed.

### Organization and System Analysis

- The dataset contains **120 organizations**.
- Finance and Healthcare were the most frequently represented industries, with **33 organizations each**.
- Windows was the most common operating system in the systems dataset, with **213 records**.
- Four users recorded the highest number of failed login attempts, with **8 attempts each**.
- The systems with the highest recorded network-event count each had **17 events**.
- **ORG079** recorded the highest number of security incidents classified as High or Critical, with **6 incidents**.
- **ORG079** also recorded the highest total incident count, with **12 incidents**.
- January recorded the highest monthly incident count, with **65 incidents**.
- December recorded the lowest monthly incident count, with **28 incidents**.
- **S0238 and S0523** had the highest numbers of Critical network alerts, with **8 alerts each**.

### Login Analysis

- Failed login attempts accounted for approximately **49.33%** of all recorded login attempts.
- A total of **73 user accounts** had at least five failed login attempts and at least one successful login.
- The IP-pattern analysis identified addresses with at least two failed login records and at least one successful login record.
- Login summaries were used to compare total attempts, failed attempts, successful attempts, and failure rates across users.

## Limitations

- The findings describe patterns in the available dataset and do not establish that any user or IP address was malicious.
- Higher incident counts do not necessarily indicate weaker security, as organization size and other relevant factors were not evaluated.
- Login frequency and failure rates alone are insufficient to confirm suspicious or malicious activity.
- Monthly incident counts show the distribution of recorded incidents but do not establish the causes of monthly differences.
- Incident counts and High/Critical incident counts provide useful indicators for further investigation but do not constitute a complete organizational risk assessment.
- Further investigation and additional context would be required before drawing operational security conclusions.

## Repository Structure

```text
1.project_analysis/
├── my_files/
│   ├── csv_files/
│   └── my_solutions/
│       ├── Creating_tables.sql
│       ├── loading_data.sql
│       └── cybersecurity_incident_analysis.sql
└── README.md
```

## SQL Concepts Used

- `SELECT`, `WHERE`, and `ORDER BY`
- Aggregate functions such as `COUNT()`
- `GROUP BY` and `HAVING`
- Joins, including `LEFT JOIN`
- Conditional aggregation using `CASE WHEN`
- Common Table Expressions (CTEs)
- Window functions such as `RANK()`
- Percentage calculations
- Date extraction using `EXTRACT()`
- Filtering aggregated results

## Conclusion

This project demonstrates the use of SQL for data aggregation, filtering, joins, common table expressions (CTEs), window functions, ranking, and percentage calculations to analyze cybersecurity-related data.

The analysis helps identify incident patterns, examine login behavior, compare security indicators across organizations and systems, and highlight areas that may warrant further investigation.

The findings describe patterns in the available dataset and do not, by themselves, confirm malicious activity or establish an organization's overall security risk.