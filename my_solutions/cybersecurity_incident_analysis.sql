-- SQLBook: Code
-- Project: Cybersecurity Incident Analysis
--
-- PROJECT CONTENTS / NAVIGATION
-- 1. Initial incident analysis and additional login/network analyses
-- 2. Analytical basics: organization count, industry distribution, operating systems
-- 3. Investigation practice questions
-- 4. Additional organization-level analyses: High/Critical counts, percentages, monthly frequency
-- 5. Advanced Investigation: suspicious IP login patterns and abnormal login frequency
--
-- NOTE ON OVERLAPPING ANALYSES
-- Some questions intentionally revisit the same metric as practice (for example, failed-login leaders,
-- industry/country incident counts, and organization High/Critical incidents). Keep the separate versions
-- where they answer a distinct learning objective; the duplicate percentage-only query has been consolidated.
-- Findings describe this dataset and should not be treated as proof of malicious activity or overall risk.

-- Question 1: Incident Severity Distribution
-- How many security incidents are recorded at each severity level?
-- Objective: Understand the distribution of incidents by severity.
select severity, count(*) as total_incidents 
from security_incidents 
group by severity;

-- finding the distribution of incidents by severity level is crucial for understanding the overall security posture of an organization. 
-- By analyzing the count of incidents at each severity level,
-- we can identify areas that may require more attention or resources. 
-- This information can help prioritize incident response efforts and improve overall cybersecurity strategies.

--1. Critical incidents have the highest count, with 140 incidents recorded.
--2: Critical and High severity incidents account for 52% of all recorded incidents.

-- Question 2: Which types of security incidents are most common in the dataset?
-- Objective: Identify the most frequently recorded security incident types to understand which categories appear most often in the dataset.
select incident_type , count(*) as total_incidents from security_incidents
group by incident_type 
order by total_incidents desc;

-- Finding : the most common incident type is 'Malware', with 185 incidents recorded

-- Question 3: What percentage of all recorded incidents are classified as Malware? 
-- Objective: Calculate the proportion of Malware incidents relative to the total number of incidents to understand its prevalence in the dataset. 
select round(count(*) * 100.0/ (select count(*) from security_incidents),2) as malware_percentage 
from security_incidents 
where incident_type = 'Malware';

-- Finding: 37% of all recorded incidents are classified as Malware. 

-- Question 4:Among Malware incidents, how many are classified as Critical or High severity? 
-- Objective: Determine the severity distribution within Malware incidents to assess the potential impact of these incidents.
select severity, count(*) as total_no_of_incidents  from security_incidents 
where incident_type = 'Malware' and severity in ('Critical','High')
group by severity
order by total_no_of_incidents desc;

-- Finding: Among Malware incidents, 49 were classified as High severity and 48 as Critical severity.

-- Question 5: What percentage of these 185 malware incidents are classified as High or Critical severity? 
-- Objective: Calculate the proportion of Malware incidents that are classified as High or Critical severity to understand the potential risk associated with these incidents.

select round(count(*)*100.0/ (select count(*) from security_incidents where incident_type = 'Malware'),2) as percentage_malware_severity
from security_incidents 
where incident_type = 'Malware' and severity in('Critical','High');

-- Finding: Among Malware incidents, 52.43% were classified as either critical or high severity 

-- Question main 1: Which industries have recorded the highest number of security incidents? 
-- Objective: Identify which industries have the highest recorded incident counts by combining incident records with organization information.
select og.industry, count(se.org_id) as total_incidents_recorded from organization as og
left join security_incidents as se
on og.org_id = se.org_id 
group by og.industry 
order by total_incidents_recorded desc; 

-- Finding: The retail industry has recorded the highest number of security incidents with a total of 147 incidents recorded 

-- Question main 2: Which countries have recorded the highest number of security incidents? 
-- objective: Identify the countries with the highest recorded incident counts by connecting security incidents to organization locations. 
select og.country, count(se.org_id) as total_incidents_recorded from organization as og 
left join security_incidents as se 
on og.org_id = se.org_id 
group by og.country 
order by total_incidents_recorded desc;

-- Finding: The United States recorded the highest number of security incidents, with 154 incidents. 

-- Question main 3: How many login attempts were successful and how many failed? 
-- Objective: Analyze the success and failure rates of login attempts to understand user authentication patterns and potential security risks.
select status, count(*) as total_attempts 
from login_logs
group by status
order by total_attempts desc;

-- Finding: There were 3,040 successful login attempts and 2,960 failed login attempts

-- Question main 4: What percentage of all login attempts are failing, and what is the failure rate?
-- objective: Calculate the failure rate of login attempts to assess the effectiveness of authentication mechanisms and identify potential security vulnerabilities.    

select round(count(*)*100.0 / (select count(*) from login_logs ),2) as failure_rate
from login_logs
where status = 'Failed';

-- Finding: The login failure rate was 49.33% of all recorded login attempts.

-- Question main 5: Which users have the highest number of failed login attempts?  
-- objective: Identify users with the highest number of failed login attempts to detect potential security threats or compromised accounts.

select user_id, count(*) as total_failed_attempts
from login_logs
where status = 'Failed'
group by user_id
order by total_failed_attempts desc
limit 5;

--Finding — Users with the Highest Number of Failed Login Attempts
--Four users — U0940, U0367, U1340, and U1281 — tied for the highest number of failed login attempts, with 8 attempts each. U1447 ranked next in the returned results, with 7 failed login attempts.
--Note: The query uses LIMIT 5, so it returns five rows rather than including every user tied at the highest count. The separate RANK() analysis identifies all four users tied for the highest number of failed login attempts.


-- Question main 6: Which users have the highest number of failed login attempts, and how do they rank compared with other users?
-- objective: Identify user accounts with unusually high failed-login activity for further security investigation. High failure counts alone do not prove malicious activity.

with ost as(select user_id, count(*) as total_failed_attempts from login_logs where status = 'Failed' group by user_id)
SELECT
    user_id,
    total_failed_attempts,
    RANK() OVER (
        ORDER BY total_failed_attempts DESC
    ) AS user_rank
FROM ost
ORDER BY user_rank, user_id;

-- Finding: Four users — U0940, U1281, U1340, and U0367 — recorded the highest number of failed login attempts, with 8 attempts each.
-- Business Implication: These accounts could be prioritized for further investigation. However, failed login attempts alone do not establish malicious activity; additional context, such as login timestamps, IP addresses, and subsequent successful logins, would be needed.
-- Limitation: This analysis identifies accounts with frequent failed login attempts but does not establish the reason for those failures.


-- Question main 7: Which users had at least 5 failed login attempts and at least 1 successful login?
-- objective: Identify accounts that experienced repeated login failures but also had a successful login during the recorded period. These accounts may warrant further investigation, though this pattern alone does not prove suspicious activity.


select user_id, count(case when status = 'Success' then 1 end) as success_attempts,
count(case when status = 'Failed' then 1 end) as failed_attempts
from login_logs 
group by user_id
having count(case when status = 'Failed' then 1 end) >= 5 and count(case when status = 'Success' then 1 end)  >= 1;

-- Finding: A total of 73 user accounts recorded at least five failed login attempts and at least one successful login during the recorded period.
-- The analysis identifies user accounts that recorded at least five failed login attempts and at least one successful login during the recorded period.
-- Business Implication: These accounts may warrant further investigation to determine whether the repeated failures followed by successful logins reflect legitimate user activity or potentially suspicious behaviour.
-- Limitation: Repeated failed login attempts followed by a successful login do not, by themselves, prove that an account has been compromised. Login timestamps, IP addresses, and other activity should be reviewed before drawing conclusions.

-- Question main 8: Which IP addresses generated the highest number of failed login attempts, and how many distinct users were associated with each IP?
-- Objective: Identify IP addresses associated with repeated login failures and multiple user accounts. This can help prioritize IPs for further investigation, although repeated failures alone do not prove malicious activity.

SELECT
    ip_address,
    COUNT(DISTINCT user_id) AS total_of_users,
    COUNT(*) AS total_failed_attempts
FROM login_logs
WHERE status = 'Failed'
GROUP BY ip_address
HAVING COUNT(*) >= 2
ORDER BY total_failed_attempts DESC;

-- Finding:A total of 68 IP addresses recorded exactly two failed login attempts each. Each of these IP addresses was associated with two distinct users, indicating one failed login attempt per user for each IP address. No IP address in the reviewed results recorded more than two failed login attempts.
--Business Implication:These IP addresses may warrant monitoring, but the available data does not establish malicious activity. Further investigation should consider login dates, successful login activity, and whether the observed behaviour differs from normal user activity.
--Limitation:The analysis is based on failed login counts and the number of distinct users per IP address. These metrics alone cannot confirm a cyberattack or establish the intent behind the failed attempts.


-- Question main 9: Which industries have the highest number of Critical and High-severity security incidents?
-- Objective: Identify which industries experience the highest number of Critical and High-severity security incidents, so the organization can identify where serious incidents are most concentrated.

with pst as
(select og.industry, count(case when se.severity in ('Critical','High') then se.incident_id end) as critical_high_incidents from organization as og 
left join security_incidents as se 
on og.org_id = se.org_id
group by og.industry

) 

select industry,critical_high_incidents, rank() over(order by critical_high_incidents desc ) as rank from pst 
order by rank asc;

--Finding — Industry-wise Critical and High-Severity Incidents
--Retail ranked first, with 79 Critical and High-severity incidents, followed by Healthcare with 67, Finance with 65, and Tech with 49. Retail had the highest count among the four industries, indicating that it accounted for the largest number of serious incidents in this dataset.
--Business implication: The organization could prioritize further investigation of security incidents in the Retail industry to understand the factors contributing to its higher incident count.

-- Question main 10: What are the top countries by security incident count, and how does the frequency of incidents vary between them?
-- Objective: Identify which countries have the highest number of security incidents and compare their incident counts.
with ost as(
select og.country, count(se.org_id) as total_incidents
from organization as og
left join security_incidents as se 
on og.org_id = se.org_id
group by  og.country 
) 
select *, rank() over(order by total_incidents desc) from ost; 

-- Finding — Country-wise Security Incidents

-- The United States ranked first with 154 security incidents, followed by the United Kingdom with 136, Germany with 106, and Canada with 104. The United States recorded the highest number of incidents among the four countries shown in the analysis.

-- Business implication: The organization could investigate why the United States has a higher incident count and assess whether this reflects a larger organizational presence, differences in reporting, or greater security risks.

-- Note: Incident counts alone do not establish that one country has weaker cybersecurity. The number of organizations and other relevant factors should also be considered.

-- Question main 11: Which users have the most successful logins, and how many successful login attempts does each user have?
-- objective: Find out which users are associated with the highest number of successful login attempts.

with dept as(
select user_id, count(*) as total_success_attempt
from login_logs 
where status = 'Success'
group by user_id
) 
select *, rank() over(order by total_success_attempt desc) as rank 
from dept
order by rank
limit 10;

-- Finding — Successful Login Activity by User

-- Users U0892 and U0510 recorded the highest number of successful login attempts, with 8 successful logins each. 
--Several other users recorded 7 successful logins each.

-- Business implication: These users had the highest successful login counts in the dataset.
-- However, a high number of successful logins does not automatically indicate suspicious activity; 
--login frequency should be assessed alongside failed attempts, timestamps, and normal user behaviour.

-- Question main 12: Which users have the highest failed login rates, and how many successful and failed login attempts did they record?
--Objective: Identify users with high failed-login rates and compare their successful and failed login attempts to help prioritize accounts for further investigation.
with ss_fs as
(
select user_id,count(case when status = 'Success' then 1 end) as successful_logins,
count(case when status = 'Failed' then 1 end) as Failed_logins, count(status) as total_attempts
from login_logs
group by user_id 
)

select user_id,successful_logins,Failed_logins, round((Failed_logins* 100.0)/(total_attempts),2)  as Failed_login_rate_pct from ss_fs
ORDER BY Failed_login_rate_pct DESC,Failed_logins DESC;

-- Finding — User-wise Failed Login Rate

-- The analysis identified several users with a 100% failed login rate, meaning that all their recorded login attempts were unsuccessful. These accounts may warrant further review to determine whether the failures resulted from user errors, access issues, or potentially suspicious activity.

-- Business implication: Prioritize accounts based on both failed login rate and the total number of failed attempts. A 100% failure rate alone does not establish malicious activity.


-- Question main 13: How many network events are recorded at each severity level, and which severity level is the most common?
-- Objective: To understand the distribution of network events by severity and identify the most frequently recorded severity level.

select severity, count(event_id) as total_recorded_events 
from network_events 
group by severity
order by total_recorded_events desc;

-- Finding: High and Critical severity events tied for the highest count, with 1,278 events each.
-- Together, they accounted for 51.12% of all 5,000 recorded network events.

-- Questions basics 1: How many organizations are in the dataset?
-- Objective: To determine the total number of organizations represented in the dataset by counting the organization records in the organization table.
select count(org_id) as total_no_of_organizations from organization;

-- Findings there are total 120 oraganization we have in this dataset 

-- Question basics 2: Which industries appear most frequently?
--Objective: To identify the industries with the highest number of organizations by counting organization records for each industry and ranking them from highest to lowest.

select industry,count(*) as total_appear 
from organization 
group by industry
order by total_appear desc;

-- Finding: Finance and Healthcare are tied for the highest number of organizations, with 33 each. Tech has the fewest, with 22.

-- Question basics 3: Which operating systems are most common?
--Objective: To identify the most frequently used operating systems in the dataset by counting the number of records associated with each operating system and ranking them from highest to lowest.

select os_type, count(*) as mostly_used_os from systems 
group by os_type
order by mostly_used_os desc;

-- Finding: Windows is the most common operating system in the systems table, with 213 records, followed by Mac (203) and Linux (184). 

-- Investigation Questions

-- Question 1: Which users have the most failed login attempts?
-- Objective: To identify users with the highest number of failed login attempts by grouping login records by user and counting failed attempts, helping flag users who may warrant further security investigation.

select user_id, count(*) as login_attempts
from login_logs 
where status = 'Failed'
group by user_id
order by login_attempts desc;

-- Finding: U1281, U1340, U0940 aur U0367 top par tied hain, with 8 failed attempts each.

-- Question 2: Which systems generate the most security events?
--Objective: To determine which systems record the highest number of security events by counting events for each system and ranking the systems from highest to lowest.

select system_id, count(*) as security_events from network_events 
group by system_id
order by security_events desc;

-- Finding: Four systems tie for the highest number of recorded security events, with 17 each.

-- Question 3: Which organizations have the most incidents?
-- Objective: To identify the organizations associated with the highest number of recorded security incidents by counting incidents for each organization and ranking them from highest to lowest. 

select org_id, count(*) as total_security_incidents 
from security_incidents 
group by org_id 
order by total_security_incidents desc;

--Finding: ORG079 has the highest number of recorded security incidents (12), followed by ORG082 (11) and ORG110 (10).

-- Question 4: Which systems are involved in the most incidents?
--Objective: To identify the systems associated with the highest number of recorded security incidents by counting incidents for each system and ranking them from highest to lowest. 

select system_id, count(distinct incident_id) as total_incidents 
from incident_systems 
group by system_id 
order by total_incidents desc; 

-- Findings: six systems are tied for the highest count, with four incidents associated with each system. 

-- Question 5: Which users have the highest number of successful login attempts?
--Objective: To identify users with the most successful logins by counting successful login records for each user and ranking them from highest to lowest. 

select user_id, count(*) as total_successful_attempts 
from  login_logs 
where status = 'Success'
group by user_id 
order by total_successful_attempts desc;

-- Finding: The analysis shows that U0892 and U0510 have the highest number of successful login attempts, with 8 attempts each. They are followed by eight users with 7 successful login attempts, while the remaining users recorded 6, 5, and 4 successful attempts, as reflected in the output.


-- Question 6: Which systems generate the highest number of critical security alerts?
-- Objective: To identify the systems with the most critical-severity network events by filtering for critical events, counting them per system, and ranking the systems from highest to lowest.

with total_sys as
(
select system_id, count(*) as total_critical_alerts 
from network_events 
where severity = 'Critical' 
group by system_id 
) 
select *, rank() over(order by total_critical_alerts desc) as alert_rank 
from total_sys 
order by alert_rank,system_id;

--Findings: The analysis indicates that S0238 and S0523 recorded the highest number of critical alerts, with 8 alerts each, making them jointly ranked first. 
--They are followed by S0107, S0186, and S0452, each with 7 critical alerts, placing them at rank 3. The absence of rank 2 is expected, as the RANK() function assigns the same rank to tied values and skips subsequent ranks accordingly. 

-- Question 7: Which industries have the highest number of security incidents?
--Objective: To compare the total number of recorded security incidents across industries and rank industries from highest to lowest. 
select *, rank() over( order by total_security_incidents desc) as ranking from (
select og.industry,count(se.incident_id) as total_security_incidents
from organization as og 
left join security_incidents as se
on og.org_id = se.org_id 
group by og.industry 
) as ost;

--Finding: The Retail sector reported the highest number of incidents (147), followed by Finance (133) and Healthcare (127), while the Tech sector recorded the lowest count (93). This indicates that incident activity is concentrated primarily within the Retail, Finance, and Healthcare sectors. 

-- Question 8: Which countries have the highest number of security incidents?
-- Objective: To compare recorded security incident counts across countries and rank them from highest to lowest.

select *, ranK() over(order by total_security_incidents desc) as Ranking 
from
(
select og.country, count(se.incident_id) as total_security_incidents 
from organization as og 
left join security_incidents as se  
on og.org_id = se.org_id
group by og.country) as ost; 

-- Finding: The USA recorded the highest number of security incidents (154) 

-- Question 9: Which organizations have the highest number of High and Critical security incidents combined?
-- Objective: To identify the organizations with the greatest number of high-severity incidents by filtering for High and Critical, counting incidents per organization, and ranking the results from highest to lowest. 

select *, rank() over(order by no_of_high_critical_incidents  desc) as Ranking from 
(
select og.org_id, count(CASE
                WHEN se.severity IN ('Critical', 'High')
                THEN se.incident_id
            END) as no_of_high_critical_incidents 
from organization as og
left join security_incidents as se  
on og.org_id = se.org_id
group by og.org_id 
) as ost;


-- Findings: Organizations with the Highest Number of High and Critical Security Incidents

-- ORG079 recorded the highest number of High and Critical security incidents, with 6 incidents.

-- Six organizations — ORG087, ORG090, ORG107, ORG078, ORG018, and ORG058 — tied for second place, with 5 incidents each.

-- 13 out of 120 organizations (10.83%) had zero High or Critical incidents.

-- The remaining 107 organizations (89.17%) had at least one High or Critical incident.

-- Conclusion: ORG079 had the highest recorded count of High and Critical security incidents. However, incident counts alone do not establish an organization's overall risk level. A complete risk assessment would also consider total incidents, incident rates, organizational size, and other relevant security indicators.



-- Question: Which organizations have the highest percentage of High and Critical incidents out of their total incidents?
-- Objective: To identify organizations where High and Critical incidents make up the largest proportion of all recorded incidents, by calculating the percentage per organization and ranking the results from highest to lowest.

WITH org_incidents AS (
    SELECT
        og.org_id,
        COUNT(se.incident_id) AS total_incidents,
        COUNT(
            CASE
                WHEN se.severity IN ('Critical', 'High')
                THEN se.incident_id
            END
        ) AS high_critical_incidents
    FROM organization AS og
    LEFT JOIN security_incidents AS se
        ON og.org_id = se.org_id
    GROUP BY og.org_id
),
org_percentages AS (
    SELECT
        org_id,
        total_incidents,
        high_critical_incidents,
        ROUND(
            100.0*high_critical_incidents/ NUllIf(total_incidents,0)
        ,2) AS high_critical_percentage
    FROM org_incidents
)
SELECT
    *,
    RANK() OVER (
        ORDER BY high_critical_percentage DESC NULLS LAST
    ) AS ranking
FROM org_percentages
ORDER BY ranking, org_id;                          


-- Findings: Percentage of High and Critical Incidents by Organization

-- - Seventeen organizations had a High/Critical incident percentage of 100%, meaning all their recorded incidents were classified as High or Critical.
-- - ORG079 recorded 12 total incidents, of which 6 were High or Critical, giving it a High/Critical incident percentage of 50%.
-- - ORG078 recorded a percentage of 55.56% (5 out of 9 incidents), while ORG107 recorded 62.50% (5 out of 8 incidents).
-- - ORG082 recorded 3 High/Critical incidents out of 11 total incidents, representing 27.27%.

-- Conclusion: Ranking by percentage highlights organizations where a greater proportion of incidents are High or Critical. However, percentages should be considered alongside total incident counts because an organization with one incident can have a 100% rate, while an organization with many more incidents may have a lower percentage.

-- Question: How does the number of security incidents change month by month?
-- Objective: Calculate the monthly incident frequency using the incident date, so we can identify which months recorded the highest and lowest numbers of incidents. 

select EXTRACT(MONTH from discovered_date) as Months ,count(*) as total_incidents from security_incidents
group by EXTRACT(MONTH from discovered_date) 
order by Months asc;

--Findings a
-- Monthly Security Incident Frequency

-- - January recorded the highest number of security incidents, with 65 incidents.
-- - December recorded the lowest number, with 28 incidents.
-- - The dataset contains 500 recorded security incidents across the 12 months.

-- These results describe the distribution of recorded incidents by month; they do not, by themselves, establish the cause of monthly differences or prove changes in security risk.

-- Question: Identify organizations with the highest risk.

-- Objective: Analyze incident severity and incident counts to identify organizations that may warrant further security investigation.

with ost as (select og.org_id,count(se.incident_id) as total_incidents, count(case when se.severity in ('Critical','High') then se.incident_id end) as high_critical_incidents
from organization as og 
left join security_incidents as se 
on og.org_id = se.org_id 
group by og.org_id ) 

select *, Rank() over(order by high_critical_incidents desc) from ost;

--Findings: Organizations with the Highest Number of High and Critical Incidents
-- ORG079 recorded the highest number of High and Critical incidents, with 6 out of 12 total incidents. Six organizations—ORG087, ORG090, ORG107, ORG078, ORG018, and ORG058—followed with 5 High and Critical incidents each.
-- Conclusion: ORG079 had the highest count of serious incidents in this dataset. However, incident counts alone do not establish overall organizational risk. Severity proportions and additional contextual indicators should also be considered.


-- Consolidated organization-risk conclusion (percentage analysis is already covered above).
-- Count-based result: ORG079 recorded the highest number of High/Critical incidents: 6 out of 12 total incidents (50.00%).
-- Six organizations—ORG087, ORG090, ORG107, ORG078, ORG018, and ORG058—recorded 5 High/Critical incidents each.
-- Percentage-based result: 17 organizations recorded a 100% High/Critical incident percentage, but each had only 1–5 total incidents.
-- ORG107 recorded 5 High/Critical incidents out of 8 total incidents (62.50%), a higher proportion than ORG079 despite having fewer serious incidents.
-- Conclusion: Count and percentage measure different aspects of the observed data. ORG079 had the highest serious-incident count, while some organizations had a higher serious-incident proportion. These metrics alone do not establish overall organizational risk; incident context, organizational size, and other security indicators should also be assessed.


--Advanced Investigation — Detect Suspicious Login Patterns by IP Address

-- Business Question:
-- Which IP addresses show potentially suspicious login patterns based on repeated failed login attempts and successful login activity?

-- Objective:  
-- To identify IP addresses associated with multiple failed login attempts and successful logins, examine the users and dates linked to these activities, and assess whether the observed patterns provide sufficient evidence to warrant further investigation.

SELECT
    ip_address,
    COUNT(*) AS total_attempts,
    COUNT(*) FILTER (
        WHERE status = 'Failed'
    ) AS failed_attempts,
    COUNT(*) FILTER (                   -- verifying total failer and successful attempts ip_address wise
        WHERE status = 'Success'
    ) AS successful_attempts
FROM login_logs
GROUP BY ip_address
HAVING COUNT(*) FILTER (
           WHERE status = 'Failed'
       ) >= 1
   AND COUNT(*) FILTER (
           WHERE status = 'Success'
       ) >= 1
ORDER BY failed_attempts DESC;

-- Main query 

SELECT
    ip_address,
    user_id,
    login_time,
    status
FROM login_logs
WHERE ip_address IN (
    SELECT ip_address
    FROM login_logs
    GROUP BY ip_address
    HAVING COUNT(*) FILTER (
        WHERE status = 'Failed'
    ) >= 2
       AND COUNT(*) FILTER (
        WHERE status = 'Success'
    ) >= 1
)
ORDER BY ip_address, login_time, user_id;



-- Finding — Login Patterns by IP Address

-- The query identified IP addresses associated with both failed and successful login attempts. In the reviewed records, three IP addresses—192.168.5.78, 192.168.44.57, and 192.168.79.86—each had two failed attempts and one successful attempt involving three different users. These attempts occurred across several months.

-- Business Implication: The reviewed patterns do not provide sufficient evidence to classify these IP addresses as suspicious. Failed attempts may result from normal user errors, and multiple users may legitimately share an IP address. Further investigation using additional security logs would be needed to assess whether malicious activity occurred.

-- Limitation: The dataset records dates but not exact timestamps, preventing analysis of the precise timing of login attempts within a day. The available records alone cannot confirm a cyberattack. 


-- Advanced Investigation — Question 2: Identify users with abnormal login frequency.
-- Objective: To identify users with unusually high login-attempt frequency by analyzing the total number of login attempts per user and comparing failed and successful attempts to highlight accounts that may require further investigation.

SELECT
    user_id,
    COUNT(*) AS total_attempts,
    COUNT(*) FILTER (WHERE status = 'Failed') AS failed_attempts,
    COUNT(*) FILTER (WHERE status = 'Success') AS success_attempts,
    ROUND(
        COUNT(*) FILTER (WHERE status = 'Failed') * 100.0
        / COUNT(*),
        2
    ) AS failure_rate
FROM login_logs
GROUP BY user_id
ORDER BY total_attempts DESC, failed_attempts DESC;


--Advanced Investigation Q2 Findings — Identify Users with Abnormal Login Frequency

--Finding: U0061 and U1447 recorded the highest login frequency, with 12 attempts each, including 7 failed attempts (58.33%). U0279 had the highest failure rate at 100%, with all 7 login attempts failing. U0367 recorded 8 failed attempts out of 9, resulting in an 88.89% failure rate. U1281, U1340, and U0940 also recorded 8 failed attempts each.
--Business implication:  These results identify users with frequent login attempts and accounts with a high proportion of failed logins that may warrant further investigation. However, high login frequency or failure rate alone does not confirm malicious activity.
--Limitation: The `login_time` column contains dates but not exact timestamps. Therefore, this analysis cannot determine whether repeated attempts occurred within unusually short periods. Additional timestamp-level logs, IP address analysis, and historical user activity would help determine whether the observed patterns are abnormal.