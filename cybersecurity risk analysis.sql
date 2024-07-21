-- create table
CREATE TABLE network_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    Source_IP VARCHAR(45) NOT NULL,
    Destination_IP VARCHAR(45) NOT NULL,
    protocol VARCHAR(10) NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    traffic_type VARCHAR(10) NOT NULL,
    source_port INT NOT NULL,
    destination_port INT NOT NULL,
    data_volume INT NOT NULL,
    packet_size INT NOT NULL,
    HTTP_status_code INT NOT NULL,
    firewall_rule VARCHAR(20) NOT NULL,
    vpn_status BOOLEAN NOT NULL,
    mfa_status VARCHAR(10) NOT NULL,
    credential_used VARCHAR(50) NOT NULL,
    data_classification VARCHAR(20) NOT NULL,
    encryption_algorithm VARCHAR(50)
);
CREATE TABLE network_logs_2 (
    linked_id INT PRIMARY KEY,
    treat_type VARCHAR(255),
    connection_status VARCHAR(50),
    security_level VARCHAR(50),
    flagged BOOLEAN,
    device_type VARCHAR(255),
    application VARCHAR(255),
    external_internal_flag BOOLEAN,
    service_name VARCHAR(255),
    file_hash VARCHAR(255),
    limited_events_id CHAR(36),  -- UUIDs are typically stored as CHAR(36) in MySQL
    ttl_value INT,
    user_behavior_score FLOAT,
    incident_category VARCHAR(255),
    cloud_service_info VARCHAR(255),
    ioc_flag BOOLEAN
);

CREATE TABLE user_activity (
    id INT AUTO_INCREMENT PRIMARY KEY,
    activity_count INT,
    suspicious_activity BOOLEAN,
    last_activity_timestamp TIMESTAMP,
    browser TEXT,
    number_of_downloads INT,
    email_sent INT
);
select*
from user_behavior;

select*
from network_logs1;

select*
from network_logs2;

-- data cleaning(identify and removing duplicate
select  Source_IP, Destination_IP, Protocol, count(*)
from network_logs1
group by Source_IP, Destination_IP, Protocol
having count(*)>1;

select Linked_ID, Threat_Type, Severity_Level, Device_Type, Connection_Status, count(*)
from network_logs2
group by Linked_ID, Threat_Type, Severity_Level, Device_Type, Connection_Status
having count(*)>1;

-- checking and removing null values accross all columns

select
count(case when Source_IP is null then 1 end) as Source_IP_Missing,
count(case when Protocol is null then 1 end) as Protocol_Missing,
count(case when Timestamp is null then 1 end) as Timestamp_IP_Missing,
count(case when Traffic_Type is null then 1 end) as Traffic_Type_Missing,
count(case when Source_Port is null then 1 end) as Source_Port_Missing,
count(case when Destination_Port is null then 1 end) as Destination_Port_Missing,
count(case when Data_Volume is null then 1 end) as Data_Volume_Missing,
count(case when Packet_Size is null then 1 end) as Packet_Size_Missing,
count(case when HTTP_Status_Code is null then 1 end) as HTTP_Status_Code_Missing,
count(case when Firewall_Rule is null then 1 end) as Firewall_Rule_Missing,
count(case when VPN_Status is null then 1 end) as VPN_Status_Missing,
count(case when VPN_Status is null then 1 end) as VPN_Status_Missing,
count(case when Credential_Used is null then 1 end) as Credential_Used_Missing,
count(case when Data_Classification is null then 1 end) as Data_Classification_Missing,
count(case when Encryption_Algorithm is null then 1 end) as Encryption_Algorithm_Missing
from network_logs1;


alter table network_logs1 add column Traffic_Category varchar(255);

update network_logs1
set Traffic_Category = case when Traffic_Type = 'inbound' then 'incoming' else 'outgoing' end;

select Traffic_Category
from network_logs1;

alter table network_logs2 add column Severity_Category varchar(50);


-- Update the Severity_Category based on the Severity_Level

UPDATE network_logs2
SET Severity_Category = 
    CASE 
        WHEN Severity_Level = 'low' THEN 'low risk'
        WHEN Severity_Level = 'medium' THEN 'medium risk'
        ELSE 'high risk'
    END;

select Severity_Category
from  network_logs2;

-- count number of severity level
select count(*)
from  network_logs2
where Severity_Category = 'high risk';

select count(*)
from  network_logs2
where Severity_Category = 'medium risk';

select count(*)
from  network_logs2
where Severity_Category = 'low risk';

-- query optimization
SELECT 
    SUM(CASE WHEN Severity_Category = 'high risk' THEN 1 ELSE 0 END) AS high_risk_count,
    SUM(CASE WHEN Severity_Category = 'medium risk' THEN 1 ELSE 0 END) AS medium_risk_count,
    SUM(CASE WHEN Severity_Category = 'low risk' THEN 1 ELSE 0 END) AS low_risk_count
FROM network_logs2;

-- identify the most frequent device used to login
SELECT Device_Type, COUNT(*) AS device_count
FROM network_logs2
GROUP BY Device_Type
ORDER BY device_count DESC;

-- identify the type of traffic with the most data volume 

select Traffic_Category,
sum(Data_Volume) as total_Data_Volume
FROM network_logs1
group by Traffic_Category
order by total_Data_Volume
desc;

-- identifying the correlation between the traffic type and data volume 

select Traffic_Type,
avg(Data_Volume)as avg_Data_Volume
FROM network_logs1
group by Traffic_Type
order by avg_Data_Volume
desc;

-- identify count of threats that were flagged and critical
select count(*) as flagged_and_critical
FROM network_logs2
where flagged = true and Asset_Classification = 'critical';

-- determin the encrypted algorithm used for sensitive data

select distinct
encryption_algorithm
from network_logs1
where Data_Classification = 'confidential';

select 
encryption_algorithm
from network_logs1;

-- count number of failed attempts

SELECT Source_IP,
       COUNT(id) AS failed_attempts,
       GROUP_CONCAT(DISTINCT Firewall_Rule ORDER BY Firewall_Rule) AS Firewall_Rules,
       GROUP_CONCAT(DISTINCT Data_Classification ORDER BY Data_Classification) AS Data_Classifications
FROM network_logs1
WHERE MFA_Status = 'failed'
GROUP BY Source_IP
ORDER BY failed_attempts DESC;

-- count logs where serverity level is critical or high 

SELECT COUNT(*)
FROM network_logs1 a
JOIN network_logs2 b ON a.ID = b.Linked_ID
WHERE b.Severity_Level IN ('high', 'critical');

-- ivestigate type of threats and severity level
select*
from network_logs2
where Threat_Type in ('DDos', 'Malware')
order by Severity_Level desc;

-- monitoring data exflitration where data classification is confidential

select a.*, b.data_exflitration_flag
from network_logs1 a
join network_logs2 b
on a.ID = b.Linked_id
where a.data_classification in ('confidential', 'highly confidential')
and b.data_exflitration_flag = '1';

select Data_Exfiltration_Flag
from network_logs2;

-- trends of different severity levels over time 
SELECT b.Severity_Level, 
       DATE_FORMAT(a.Timestamp, '%Y-%m') AS month,
       COUNT(*) AS Event_count
FROM network_logs1 a
JOIN network_logs2 b ON a.ID = b.Linked_id
GROUP BY b.Severity_Level, DATE_FORMAT(a.Timestamp, '%Y-%m')
ORDER BY month ASC, Event_count DESC;

-- count of MFA attempts within a time window 
select Source_IP, count(ID) as failed_attempts
FROM network_logs1
where MFA_Status = 'failed'
and Timestamp between '2023-01-01' and '2023-02-01'
group by Source_IP
order by failed_attempts
desc;

-- user with multiple downloads
select*
from user_behavior
where number_of_downloads>5
and activity_count>50;

-- firewall rule effect 
select Firewall_Rule, count(*) as rule_trigger_count
from network_logs1
group by Firewall_Rule
ORDER BY rule_trigger_count desc;

-- avg user behaviour score of diffrent threat type 

select b.Threat_Type, avg(b.user_behavior_score) as avg_user_behavior_score
from network_logs1 a
join network_logs2 b
on a.ID = b.Linked_ID
group by b.Threat_Type
order by avg_user_behavior_score;

-- trend of high or critical threat by protocol and months 
DELIMITER $$

CREATE PROCEDURE fetch_critical_high_trends ()
BEGIN
    SELECT DATE_FORMAT(A.Timestamp, '%Y-%m-01') AS Month, 
           A.protocol AS protocol,
           COUNT(*) AS critical_high_count
    FROM network_logs1 A
    JOIN network_logs2 B ON A.ID = B.Linked_ID
    WHERE B.Severity_Level IN ('High', 'Critical')
    GROUP BY Month, A.protocol
    ORDER BY Month, critical_high_count DESC;
END$$

DELIMITER ;

DELIMITER $$
select * 
from fetch_critical_high_trends ()
DELIMITER ;

DELIMITER $$
drop function if exists 
fetch_critical_high_trends ()
DELIMITER ;