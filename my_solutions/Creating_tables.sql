#creating tables for the project database 
create table organization(
    org_id varchar(30) primary key,
    industry varchar(50) ,
    country varchar(50),
) # organization table to store organization details 

create table security_incidents(
    incident_id VARCHAR(30) primary key,
    org_id varchar(30) references organization(org_id),
    incident_type varchar(70),
    discovered_date Date,
    severity varchar(30)
) # security incidents table to store security incident details

create table systems(
    system_id varchar(30) primary key,
    org_id varchar(30) references organization(org_id),
    os_type varchar(40),
    criticality varchar(40)
)# systems table to store system details 

create table users(
    user_id varchar(30) primary key,
    org_id varchar(30) REFERENCES organization(org_id),
    role varchar(70)
)  # users table to store user details 

create table network_events(
    event_id varchar(30) primary key,
    system_id varchar(30) references systems(system_id),
    event_type varchar(70),
    timestamp  TIMESTAMP,
    severity varchar(40)
) # network events table to store network event details 

create table login_logs(
    login_id varchar(30) primary key,
    user_id varchar(30) references users(user_id),
    login_time Date,
    ip_address inet,
    status VARCHAR(30)
);

# changing the data type of the timestamp column in the network_events table from TIMESTAMP to DATE to store only the date part of the timestamp.
# This is done using the ALTER TABLE command with the ALTER COLUMN clause, specifying the new data type and using a conversion expression to convert existing timestamp values to date values.
Alter table network_events 
Alter column timestamp type Date 
USING timestamp::DATE

select * from network_events;