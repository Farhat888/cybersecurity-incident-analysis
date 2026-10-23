-- Project: Cybersecurity Incident Analysis
-- Question 1: Incident Severity Distribution
-- How many security incidents are recorded at each severity level?
-- Objective: Understand the distribution of incidents by severity.
select severity, count(*) as total_incidents 
from security_incidents 
group by severity

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
order by total_incidents desc

-- Finding : the most common incident type is 'Malware', with 185 incidents recorded

-- Question 3: What percentage of all recorded incidents are classified as Malware? 
-- Objective: Calculate the proportion of Malware incidents relative to the total number of incidents to understand its prevalence in the dataset. 
select round(count(*) * 100.0/ (select count(*) from security_incidents),2) as malware_percentage 
from security_incidents 
where incident_type = 'Malware'

-- Finding: 37% of all recorded incidents are classified as Malware. 

-- Question 4:Among Malware incidents, how many are classified as Critical or High severity? 
-- Objective: Determine the severity distribution within Malware incidents to assess the potential impact of these incidents.
select severity, count(*) as total_no_of_incidents  from security_incidents 
where incident_type = 'Malware' and severity in ('Critical','High')
group by severity
order by total_no_of_incidents desc 

-- Finding: Among Malware incidents, 49 were classified as High severity and 48 as Critical severity.

-- Question 5: What percentage of these 185 malware incidents are classified as High or Critical severity? 
-- Objective: Calculate the proportion of Malware incidents that are classified as High or Critical severity to understand the potential risk associated with these incidents.

select round(count(*)*100.0/ (select count(*) from security_incidents where incident_type = 'Malware'),2) as percentage_malware_severity
from security_incidents 
where incident_type = 'Malware' and severity in('Critical','High')

-- Finding: Among Malware incidents, 52.43% were classified as either critical or high severity 

-- Question main 1: Which industries have recorded the highest number of security incidents? 
-- Objective: Identify which industries have the highest recorded incident counts by combining incident records with organization information.
select og.industry, count(se.org_id) as total_incidents_recorded from organization as og
left join security_incidents as se
on og.org_id = se.org_id 
group by og.industry 
order by total_incidents_recorded desc 

-- Finding: The retail industry has recorded the highest number of security incidents with a total of 147 incidents recorded 

-- Question main 2: Which countries have recorded the highest number of security incidents? 
-- objective: Identify the countries with the highest recorded incident counts by connecting security incidents to organization locations. 
select og.country, count(se.org_id) as total_incidents_recorded from organization as og 
left join security_incidents as se 
on og.org_id = se.org_id 
group by og.country 
order by total_incidents_recorded desc 

-- Finding: The United States recorded the highest number of security incidents, with 154 incidents. 

-- Question main 3: How many login attempts were successful and how many failed? 
-- Objective: Analyze the success and failure rates of login attempts to understand user authentication patterns and potential security risks.
select status, count(*) as total_attempts 
from login_logs
group by status
order by total_attempts desc

-- Finding: There were 3,040 successful login attempts and 2,960 failed login attempts

-- Question main 4: What percentage of all login attempts are failing, and what is the failure rate?
-- objective: Calculate the failure rate of login attempts to assess the effectiveness of authentication mechanisms and identify potential security vulnerabilities.    

select round(count(*)*100.0 / (select count(*) from login_logs ),2) as failure_rate
from login_logs
where status = 'Failed' 

-- Finding: The login failure rate was 49.33% of all recorded login attempts.

-- Question main 5: Which users have the highest number of failed login attempts?  
-- objective: Identify users with the highest number of failed login attempts to detect potential security threats or compromised accounts.

select user_id, count(*) as total_failed_attempts
from login_logs
where status = 'Failed'
group by user_id
order by total_failed_attempts desc
limit 5 

-- Finding: The top 5 users with the highest number of failed login attempts are: U0940 

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
having count(case when status = 'Failed' then 1 end) >= 5 and count(case when status = 'Success' then 1 end)  >= 1

-- Finding: A total of 73 user accounts recorded at least five failed login attempts and at least one successful login during the recorded period.
-- The analysis identifies user accounts that recorded at least five failed login attempts and at least one successful login during the recorded period.
-- Business Implication: These accounts may warrant further investigation to determine whether the repeated failures followed by successful logins reflect legitimate user activity or potentially suspicious behaviour.
-- Limitation: Repeated failed login attempts followed by a successful login do not, by themselves, prove that an account has been compromised. Login timestamps, IP addresses, and other activity should be reviewed before drawing conclusions.

-- Question main 8: Which IP addresses generated the highest number of failed login attempts, and how many distinct users were associated with each IP?
-- Objective: Identify IP addresses associated with repeated login failures and multiple user accounts. This can help prioritize IPs for further investigation, although repeated failures alone do not prove malicious activity.

select ip_address,count(distinct user_id) as total_of_users, count(*) as total_failed_attempts 
from login_logs 
where status = 'Failed'
group by ip_address 
having count(*) >= 2
order by total_failed_attempts desc

-- Finding: Out of 2,892 IP addresses associated with failed login attempts, 68 recorded exactly two failed attempts each.
-- Each of these 68 IP addresses was associated with two distinct user IDs, with one failed attempt per user.
-- The remaining 2,824 IP addresses recorded one failed attempt each. No IP address recorded more than two failed attempts in this dataset.


-- Question main 9: Which industries have the highest number of Critical and High-severity security incidents?
-- Objective: Identify which industries experience the highest number of Critical and High-severity security incidents, so the organization can identify where serious incidents are most concentrated.

with pst as
(select og.industry, count(*) as critical_high_incidents from organization as og 
left join security_incidents as se 
on og.org_id = se.org_id
where se.severity in ('Critical','High')
group by og.industry

) 

select industry,critical_high_incidents, rank() over(order by critical_high_incidents desc ) as rank from pst 
order by rank asc 

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
select *, rank() over(order by total_incidents desc) from ost 

-- Finding — Country-wise Security Incidents

-- The United States ranked first with 154 security incidents, followed by the United Kingdom with 136, Germany with 106, and Canada with 104. The United States recorded the highest number of incidents among the four countries in the dataset.

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
limit 10 

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

