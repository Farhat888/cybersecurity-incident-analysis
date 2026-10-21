
# loading a data from a csv file into a table in PostgreSQL using the COPY command. The command specifies the file path, format, and indicates that the first row contains headers. After loading the data, it selects all records from the organization table to verify the import.
COPY organization 
FROM 'c:\Program Files\PostgreSQL\14\files_my\organizations.csv'
WITH (FORMAT csv, HEADER true)
# loading data from a csv file organizations.csv into the organization table
select * from organization;

copy security_incidents
from 'c:\Program Files\PostgreSQL\14\files_my\security_incidents.csv'
with (Format csv, Header true) # loading data into security_incidents from csv file security_incisdents.csv

select * from security_incidents;

# loading data from a csv file systems.csv into the systems table
copy systems 
from 'c:\Program Files\PostgreSQL\14\files_my\systems.csv'
with (Format csv, Header true)

select * from systems;

# loading data from a csv file users.csv into the users table
copy users
from 'c:\Program Files\PostgreSQL\14\files_my\users.csv'
with (Format csv, Header true)

select * from users;

# loading data from a csv file network_events.csv into the network_events table
copy network_events 
from 'c:\Program Files\PostgreSQL\14\files_my\network_events.csv'
with (Format csv, Header true)

select * from network_events;

# loading data from a csv file login_logs.csv into the login_logs table
copy login_logs 
from 'c:\Program Files\PostgreSQL\14\files_my\login_logs.csv'
with (Format csv, Header true)

select * from login_logs;

# loading data from a csv file incident_systems.csv into the incident_systems table
copy incident_systems 
from  'c:\Program Files\PostgreSQL\14\files_my\incident_systems.csv'
with (Format csv, Header true)

select * from incident_systems;

