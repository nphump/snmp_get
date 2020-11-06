
//Synopsis:
//Windows program to inerrogate SNMP sources

//Compilation:
//cl.exe /Ox /MT /EHsc snmp_get.cpp  mgmtapi.lib snmpapi.lib

#include <stdio.h>
#include "snmp.h"
#include "mgmtapi.h"

// If a response is received from the SNMP agent for each requested OID, the command returns the values of each OID (or a blank line) 
// to STDOUT (one line for each OID in the order they were passed as arguments) and exits with code 0.
// Errors messages are written to STDERR. If a serious error occurs, the program aborts and exits with code 1.

int main(int argc, char* argv[])
{
	int oid_index;
	int rc = 0;
	char* community;
	int ms_timeout;
	int retries;
	char* address;
	char* oid;
	LPSNMP_MGR_SESSION session = NULL;

	try
	{
		if (argc < 6)
		{
			fprintf(stderr, "\nSNMP_GET Copyright Solent Technology 2005\n\n");
			fprintf(stderr, "Usage:\nsnmp_get <IP_ADDRESS> <COMMUNITY> <MS_TIMEOUT> <RETRIES> <OID> [<OID> ..]\n");
			throw 1;
		}

		address = argv[1];
		community = argv[2];
		ms_timeout = atoi(argv[3]);
		retries = atoi(argv[4]);
		
		session = SnmpMgrOpen(address, community, ms_timeout, retries);
		if (! session)
		{
			unsigned long err = GetLastError();
			if (err == SNMP_MGMTAPI_TIMEOUT)
				fprintf(stderr, "Timeout\n");
			else
				fprintf(stderr, "SnmpMgrOpen() failed, error %u\n", err);

			throw 1;
		}

		for (oid_index = 5; oid_index < argc; oid_index++)
		{
			oid = argv[oid_index];

			AsnInteger errorStatus;
			AsnInteger errorIndex;
			RFC1157VarBindList varBinds;
			varBinds.list = NULL;
			varBinds.len = 0;
			AsnObjectIdentifier reqObject;
			SNMPAPI api = NULL;

			// Convert the string representation to an internal representation
			if (! SnmpMgrStrToOid(oid, &reqObject))
			{
				fprintf(stderr, "Invalid oid specified: %s\n", oid);
				throw 1;
			}
			
			// Since successful, add to the variable bindings list
			varBinds.len = 1;
			varBinds.list = (RFC1157VarBind*) SNMP_realloc(varBinds.list, sizeof(RFC1157VarBind));
			if (! varBinds.list)
			{
				fprintf(stderr, "SNMP_realloc() failed\n");
				throw 1;
			}
			varBinds.list[0].name = reqObject;
			varBinds.list[0].value.asnType = ASN_NULL;

			api = SnmpMgrRequest(
				session,
				SNMP_PDU_GET,
				&varBinds,
				&errorStatus,
				&errorIndex
			);

			if (! api)
			{
				unsigned long err = GetLastError();
				if (err == SNMP_MGMTAPI_TIMEOUT)
					fprintf(stderr, "Timeout\n");
				else
					fprintf(stderr, "SnmpMgrRequest() failed, error %u\n", err);

				throw 1;
			}

			if (errorStatus > 0)
			{
				fprintf(stderr, "Failed to get value for %s: ", oid);
				switch (errorStatus)
				{
				case SNMP_ERRORSTATUS_TOOBIG:
					fprintf(stderr, "target SNMP system could not place the results into a single SNMP message\n");
					break;

				case SNMP_ERRORSTATUS_NOSUCHNAME:
					fprintf(stderr, "oid unknown to target SNMP system\n");
					break;

				default:
					fprintf(stderr, "SNMP error %d\n", errorStatus);
				}

				fprintf(stdout, "\n");
			}
			else
			{
				// Display resulting variable
				SnmpUtilPrintAsnAny(&varBinds.list[0].value);
			}

			if (varBinds.list) SnmpUtilVarBindListFree(&varBinds); 
		}
	}
	catch (int except)
	{
		rc = except;
	}

	if (session) SnmpMgrClose(session);

	return rc;
}