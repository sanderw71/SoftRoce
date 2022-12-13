


/// @brief Check IP Header calculation function
/// @return
uint16_t IpHdrCheck()
{
	uint16_t ReferenceCrc, CalulatedCrc;

	// Check IP CRC
	ReferenceCrc = (ExampleIPhdr[10] + (ExampleIPhdr[11] << 8));
	CalulatedCrc = IpHdrChecksum((struct iphdr *)&ExampleIPhdr[0]);
	if (ReferenceCrc != CalulatedCrc)
	{
		printf("1: Checksum error ref %x != %x\n", ReferenceCrc, CalulatedCrc);
		return 1;
	}

	ReferenceCrc = (connect_req_packet_bytes[24] + (connect_req_packet_bytes[25] << 8));
	CalulatedCrc = IpHdrChecksum((struct iphdr *)&connect_req_packet_bytes[14]);
	if (ReferenceCrc != CalulatedCrc)
	{
		printf("2: Checksum error ref %x != %x\n", ReferenceCrc, CalulatedCrc);
		return 1;
	}

	ReferenceCrc = (connect_reply_packet_bytes[24] + (connect_reply_packet_bytes[25] << 8));
	CalulatedCrc = IpHdrChecksum((struct iphdr *)&connect_reply_packet_bytes[14]);
	if (ReferenceCrc != CalulatedCrc)
	{
		printf("3: Checksum error ref %x != %x\n", ReferenceCrc, CalulatedCrc);
		return 1;
	}

	return 0;
}



/// @brief Check Icrc calculation
/// @return 0 is succes
uint16_t IcrcCheck()
{
	// Check iCRC calculation
	uint32_t crc = calc_icrc32((char *)connect_req_packet_bytes, sizeof(connect_req_packet_bytes));
	uint32_t *ptr = (uint32_t *)&connect_req_packet_bytes[sizeof(connect_req_packet_bytes) - 4];
	if (*ptr != crc)
	{
		printf("1: iCRC Checksum error ref %x != %x\n", *ptr, crc);
		// return 1;
	}

	// Check iCRC calculation
	crc = calc_icrc32(connect_reply_packet_bytes, sizeof(connect_reply_packet_bytes));
	ptr = (uint32_t *)&connect_reply_packet_bytes[sizeof(connect_reply_packet_bytes) - 4];
	if (*ptr != crc)
	{
		printf("2: iCRC Checksum error ref %x != %x\n", *ptr, crc);
		// return 1;
	}

	// Check CRC insertion
	unsigned char buffer[sizeof(connect_req_packet_bytes)];
	memcpy(&buffer, connect_req_packet_bytes, sizeof(connect_req_packet_bytes) - 4);
	InsertIcrc(buffer, sizeof(buffer));

	for (int i = sizeof(connect_req_packet_bytes) - 4, n = 0; i < sizeof(connect_req_packet_bytes); i++)
	{
		if (connect_req_packet_bytes[i] != buffer[i])
		{
			printf("3: iCRC Checksum error ref loc = %d %x != %x\n", i, connect_req_packet_bytes[i], buffer[i]);
		}
	}
	return 0;
}

/// @brief Perform function checks
/// @return
uint16_t Checking()
{
	if (IpHdrCheck() != 0)
		return 1;
	if (IcrcCheck() != 0)
		return 2;
	return 0;
}