
-- declare our protocol
mes_proto = Proto("Windhager", "Windhager MES-WiFi LON Protocol")

function getTime(buffer, pos)
    local tm_sec = buffer(pos,4):le_uint();
    pos = pos + 4;
    local tm_min = buffer(pos,4):le_uint();
    pos = pos + 4;
    local tm_hour = buffer(pos,4):le_uint();
    pos = pos + 4;
    local tm_mday = buffer(pos,4):le_uint();
    pos = pos + 4;
    local tm_mon = buffer(pos,4):le_uint();
    pos = pos + 4;
    local tm_year = buffer(pos,4):le_uint();
    pos = pos + 4;
    local tm_wday = buffer(pos,4):le_uint();
    pos = pos + 4;
    local tm_yday = buffer(pos,4):le_uint();
    pos = pos + 4;
    local tm_isdst = buffer(pos,4):le_uint();
    pos = pos + 4;
    
    if(tm_sec > 60 or tm_min > 60 or tm_hour > 24 or tm_mday > 31 or tm_mon > 11 or tm_year > 300) then
        return "failed";
    end

    return string.format("%02d", tm_mday) .. "." .. string.format("%02d", tm_mon+1) .. ".".. (tm_year + 1900) .. " " .. string.format("%02d", tm_hour).. ":" .. string.format("%02d", tm_min) .. ":" .. string.format("%02d", tm_sec);
end

-- create a function to dissect it
function mes_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "MES-WiFi"
    local subtree = tree:add(mes_proto, buffer(), "MES-WiFi LON")
    local meswifi = subtree:add(mes_proto, buffer(), "Frame Info")
    local pos = 0;
    local msgType = buffer(pos,1):le_uint();
    
    local msgTypes = { "System report", "LON Frame" }
    local errorCodes = { "none", "Bit time exceeded (stop bit)", "Bit time too short", "Bit phase error", "Buffer overflow", "Sync failed", "CRC Error" }
    
    meswifi:add(buffer(pos,1),"Message type: " .. msgType .. " (".. msgTypes[msgType] .. ")")
    pos = pos + 1;
    
    local info = "";
    local bitTiming = 80/4;
    
    if(msgType == 1) then
        bitLen = buffer(pos,4):le_uint();
        meswifi:add(buffer(pos,4),"Bit length 0 min:    " .. bitLen .. "(" .. string.format("%02.2f",bitLen/bitTiming) .. "us)")
        pos = pos + 4;
        bitLen = buffer(pos,4):le_uint();
        meswifi:add(buffer(pos,4),"Bit length 0 avg:    " .. bitLen .. "(" .. string.format("%02.2f",bitLen/bitTiming) .. "us)")
        pos = pos + 4;
        bitLen = buffer(pos,4):le_uint();
        meswifi:add(buffer(pos,4),"Bit length 0 max:    " .. bitLen .. "(" .. string.format("%02.2f",bitLen/bitTiming) .. "us)")
        pos = pos + 4;
        bitLen = buffer(pos,4):le_uint();
        meswifi:add(buffer(pos,4),"Bit length 1 min:    " .. bitLen .. "(" .. string.format("%02.2f",bitLen/bitTiming) .. "us)")
        pos = pos + 4;
        bitLen = buffer(pos,4):le_uint();
        meswifi:add(buffer(pos,4),"Bit length 1 avg:    " .. bitLen .. "(" .. string.format("%02.2f",bitLen/bitTiming) .. "us)")
        pos = pos + 4;
        bitLen = buffer(pos,4):le_uint();
        meswifi:add(buffer(pos,4),"Bit length 1 max:    " .. bitLen .. "(" .. string.format("%02.2f",bitLen/bitTiming) .. "us)")
        pos = pos + 4;
        rcvd = buffer(pos,4):le_uint();
        meswifi:add(buffer(pos,4),"Packets received:    " .. rcvd)
        pos = pos + 4;
        crcerr = buffer(pos,4):le_uint();
        meswifi:add(buffer(pos,4),"Packets CRC Errors:  " .. crcerr .. " (" ..  string.format("%02.2f",crcerr*100/rcvd) .. "%)")
        pos = pos + 4;
        
        local val = buffer(pos,4):le_uint();
        meswifi:add(buffer(pos,4),"Free heap:           " .. val)
        pos = pos + 4;
        val = buffer(pos,4):le_uint();
        meswifi:add(buffer(pos,4),"Max heap:            " .. val)
        pos = pos + 4;
        val = buffer(pos,4):le_uint();
        meswifi:add(buffer(pos,4),"Free PSRAM:          " .. val)
        pos = pos + 4;
        val = buffer(pos,4):le_uint();
        meswifi:add(buffer(pos,4),"Max PSRAM:           " .. val)
        pos = pos + 4;
        
        
        local timeString = getTime(buffer, pos);
        meswifi:add(buffer(pos,4*9),"Startup time:        " .. timeString);
        pos = pos + 36;
        timeString = getTime(buffer, pos);
        meswifi:add(buffer(pos,4*9),"Statistics start:    " .. timeString);
        pos = pos + 36;
        val = buffer(pos,4):le_uint();
        meswifi:add(buffer(pos,4),"Ignites/24h:           " .. val)
        pos = pos + 4;
        
        local timesStart = pos;
        local times = "";
        local ignites = "";
        for hour=0,23 do
            times = times .. " "..string.format("%02d", hour);
        end
        for hour=0,23 do 
            local sum = 0;
            for hour_sub=0,11 do 
                sum = sum + buffer(pos + hour_sub,1):le_uint();
            end
            ignites = ignites .. " "..string.format("%02d", sum);
            pos = pos + 12;
        end
        meswifi:add(buffer(timesStart,pos - timesStart),"   Time:    " .. times)
        meswifi:add(buffer(timesStart,pos - timesStart),"   Ignites: " .. ignites)
        
        val = buffer(pos,4):le_uint();
        meswifi:add(buffer(pos,4),"Temperature:           " .. string.format("%02.2f", val / 100.0))
        pos = pos + 4;
        
        pinfo.cols['info'] = "System report";
        
    elseif (msgType == 2) then
        local ppdu = subtree:add(mes_proto,buffer(),"PPDU")
        local npdu = ppdu:add(mes_proto,buffer(),"NPDU")
        local address = npdu:add(mes_proto,buffer(),"Address")
        local domain = npdu:add(mes_proto,buffer(),"Domain")
    
        NV = {};
        TPDU = {};
        SPDU = {};
        APDU = {};
        AuthPDU = {};
        NPDU = {};
        PPDU = {};
        Address = {};
        
        local errorCode = buffer(pos,1):uint();
        
        meswifi:add(buffer(pos,1),"Error code:   " .. errorCode .. " (".. errorCodes[buffer(pos,1):uint() + 1] .. ")")
        pos = pos + 1;
        meswifi:add(buffer(pos,2),"Bits sampled: " .. buffer(pos,2):le_uint())
        pos = pos + 2;
        bitLen = buffer(pos,2):le_uint();
        meswifi:add(buffer(pos,2),"Bit duration: " .. bitLen .. "(" .. string.format("%02.2f",bitLen/8) .. "us)")
        pos = pos + 2;
        
        if(errorCode > 1) then
            return;
        end
        PPDU.Prior = buffer(pos,1):bitfield(0, 1);
        PPDU.AltPath = buffer(pos,1):bitfield(1, 1);
        PPDU.DeltaBL = buffer(pos,1):bitfield(2, 6);
        ppdu:add(buffer(pos,1),"Prior:   " .. PPDU.Prior)
        ppdu:add(buffer(pos,1),"AltPath: " .. PPDU.AltPath)
        ppdu:add(buffer(pos,1),"DeltaBL: " .. PPDU.DeltaBL)
        pos = pos + 1;
        
        NPDU.Version = buffer(pos,1):bitfield(0, 2);
        NPDU.PDUFmt = buffer(pos,1):bitfield(2, 2);
        NPDU.AddrFmt = buffer(pos,1):bitfield(4, 2);
        NPDU.Length = buffer(pos,1):bitfield(6, 2);
        pos = pos + 1;
        
        npdu:add(buffer(pos,1),"Version: " .. NPDU.Version)
        npdu:add(buffer(pos,1),"PDUFmt:  " .. NPDU.PDUFmt)
        npdu:add(buffer(pos,1),"AddrFmt: " .. NPDU.AddrFmt)
        npdu:add(buffer(pos,1),"Length:  " .. NPDU.Length)
        
        
        if(NPDU.AddrFmt == 0) then
            Address.SrcSubnet = buffer(pos,1):bitfield(0, 8);
            address:add(buffer(pos,1),"SrcSubnet:  " .. Address.SrcSubnet)
            pos = pos + 1;
            Address.SrcNode = buffer(pos,1):bitfield(1, 7);
            address:add(buffer(pos,1),"SrcNode:    " .. Address.SrcNode)
            pos = pos + 1;
            Address.DstSubnet = buffer(pos,1);
            address:add(buffer(pos,1),"DstSubnet:  " .. Address.DstSubnet)
            pos = pos + 1;
        elseif(NPDU.AddrFmt == 1) then
            Address.SrcSubnet = buffer(pos,1):bitfield(0, 8);
            address:add(buffer(pos,1),"SrcSubnet:  " .. Address.SrcSubnet)
            pos = pos + 1;
            Address.SrcNode = buffer(pos,1):bitfield(1, 7);
            address:add(buffer(pos,1),"SrcNode:    " .. Address.SrcNode)
            pos = pos + 1;
            Address.DstSubnet = buffer(pos,1);
            address:add(buffer(pos,1),"DstSubnet:  " .. Address.DstSubnet)
            pos = pos + 1;
        elseif(NPDU.AddrFmt == 2) then
            Address.SrcSubnet = buffer(pos,1):bitfield(0, 8);
            address:add(buffer(pos,1),"SrcSubnet:  " .. Address.SrcSubnet)
            pos = pos + 1;
            Address.SubType = buffer(pos,1):bitfield(0, 1);
            Address.SrcNode = buffer(pos,1):bitfield(1, 7);
            address:add(buffer(pos,1),"SrcNode:    " .. Address.SrcNode)
            pos = pos + 1;
            Address.DstSubnet = buffer(pos,1);
            address:add(buffer(pos,1),"DstSubnet:  " .. Address.DstSubnet)
            pos = pos + 1;
            Address.DstNode = buffer(pos,1):bitfield(1, 7);
            address:add(buffer(pos,1),"DstNode:    " .. Address.DstNode)
            pos = pos + 1;
            
            if(Address.SubType == 0) then
                Address.Group = buffer(pos,1);
                address:add(buffer(pos,1),"Group:        " .. Address.Group)
                pos = pos + 1;
                Address.GroupMember = buffer(pos,1);
                address:add(buffer(pos,1),"GroupMember:  " .. Address.GroupMember)
                pos = pos + 1;
            end
        elseif(NPDU.AddrFmt == 3) then
            Address.SrcSubnet = buffer(pos,1):bitfield(0, 8);
            address:add(buffer(pos,1),"SrcSubnet:  " .. Address.SrcSubnet)
            pos = pos + 1;
            Address.SrcNode = buffer(pos,1):bitfield(1, 7);
            address:add(buffer(pos,1),"SrcNode:    " .. Address.SrcNode)
            pos = pos + 1;
            Address.DstSubnet = buffer(pos,1);
            address:add(buffer(pos,1),"DstSubnet:  " .. Address.DstSubnet)
            pos = pos + 1;
            Address.NeuronID = buffer(pos,6);
            address:add(buffer(pos,1),"NeuronID:   " .. Address.NeuronID)
            pos = pos + 6;
        end
        
        info = info .. "Src: " .. Address.SrcNode;
        
        if(NPDU.Length == 0) then
            NPDU.Domain = "";
        elseif(NPDU.Length == 1) then
            NPDU.Domain = buffer(pos,1);
            domain:add(buffer(pos,1),"Domain: " .. NPDU.Domain .. " (8 bits)");
            pos = pos + 1;
        elseif(NPDU.Length == 2) then
            NPDU.Domain = buffer(pos,3);
            domain:add(buffer(pos,3),"Domain: " .. NPDU.Domain .. " (24 bits)");
            pos = pos + 3;
        elseif(NPDU.Length == 3) then
            NPDU.Domain = buffer(pos,6);
            domain:add(buffer(pos,6),"Domain: " .. NPDU.Domain .. " (48 bits)");
            pos = pos + 6;
        end
        
        if(NPDU.PDUFmt == 0) then
            local tpdu = npdu:add(mes_proto,buffer(),"PDUFmt: TPDU")
            tpdu:add(buffer(pos),"TPDU (not implemented)");
        elseif(NPDU.PDUFmt == 1) then
            local spdu = npdu:add(mes_proto,buffer(),"PDUFmt: SPDU")
            
            SPDU.Auth = buffer(pos,1):bitfield(0, 1);
            SPDU.SPDUtype = buffer(pos,1):bitfield(1, 3);
            SPDU.TransNo = buffer(pos,1):bitfield(4, 4);
            
            spdu:add(buffer(pos,1),"Auth:     " .. SPDU.Auth);
            spdu:add(buffer(pos,1),"SPDUtype: " .. SPDU.SPDUtype);
            spdu:add(buffer(pos,1),"TransNo:  " .. SPDU.TransNo);
            
            pos = pos + 1;
            
            if(SPDU.SPDUtype == 0) then
                spdu:add(buffer(pos,1),"SPDUtype:     REQUEST");
                local apdu = buffer(pos,2);
                info = info .. " | " .. "REQUEST";
                
                if(apdu:bitfield(0, 2) == 0) then
                    local remain = buffer:len() - pos - 1 - 2;
                    local remainBuffer = buffer(pos+1,remain);
                    local id = apdu:bitfield(2, 6);
                    local nmType = "APDU Type:    generic application message #"..id;
                    spdu:add(buffer(pos,1),nmType);
                    spdu:add(remainBuffer, "APDU Data:    " .. remainBuffer:bytes():tohex());
                    info = info .. " | " .. nmType;
                elseif(apdu:bitfield(0, 2) == 2) then
                    local remain = buffer:len() - pos - 2 - 2;
                    local remainBuffer = buffer(pos+1,remain);
                    local id = apdu:bitfield(2, 14);
                    local nmType = "APDU Type:    network variable message IN #"..id;
                    spdu:add(buffer(pos,1),nmType);
                    spdu:add(remainBuffer, "APDU Data:    " .. remainBuffer:bytes():tohex());
                    info = info .. " | " .. nmType;
                elseif(apdu:bitfield(0, 2) == 3) then
                    local remain = buffer:len() - pos - 2 - 2;
                    local remainBuffer = buffer(pos+1,remain);
                    local id = apdu:bitfield(2, 14);
                    local nmType = "APDU Type:    network variable message OUT #"..id;
                    spdu:add(buffer(pos,1),nmType);
                    spdu:add(remainBuffer, "APDU Data:    " .. remainBuffer:bytes():tohex());
                    info = info .. " | " .. nmType;
                elseif(apdu:bitfield(0, 3) == 3) then
                    spdu:add(buffer(pos,1),"APDU Type:  NM request/command");
                    pos = pos + 1;
                    
                    local command = apdu:bitfield(3, 5);
                    
                    if(command == 1) then
                        local nmType = "NM Type:     Query ID";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 2) then
                        local nmType = "NM Type:     Respond to query";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command ==3) then
                        local nmType = "NM Type:     Update domain";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 4) then
                        local nmType = "NM Type:     Leave domain";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 4) then
                        local nmType = "NM Type:     Update key";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 7) then
                        local nmType = "NM Type:     Query address";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 8) then
                        local nmType = "NM Type:     Query network variable config";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 9) then
                        local nmType = "NM Type:     Update group address";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 10) then
                        local nmType = "NM Type:     Query Domain";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 11) then
                        local nmType = "NM Type:     Update network variable config";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 12) then
                        local nmType = "NM Type:     Set node mode";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 13) then
                        local nmType = "NM Type:     Read memory";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 14) then
                        local nmType = "NM Type:     Write memory";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 15) then
                        local nmType = "NM Type:     Recalculate checksum";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 16) then
                        local nmType = "NM Type:     Install";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 17) then
                        local nmType = "NM Type:     Memory refresh";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 18) then
                        local nmType = "NM Type:     Query standard network variable type";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 19) then
                        local nmType = "NM Type:     Network variable fetch";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                        
                        local payload = "NM Index:    " .. buffer(pos,1);
                        spdu:add(buffer(pos,1),payload);
                        info = info .. " | " .. payload;
                        pos = pos + 1;
                        
                    elseif(command == 20) then
                        local nmType = "NM Type:     Router mode";
                        info = info .. " | " .. nmType;
                    else
                        local nmType = "NM Type:     unknown (".. command ..")";
                        info = info .. " | " .. nmType;
                    end
                elseif(apdu:bitfield(0, 4) == 5) then
                    local nmType = "APDU Type:    ND message";
                    spdu:add(buffer(pos,1),nmType);
                    info = info .. " | " .. nmType;
                elseif(apdu:bitfield(0, 4) == 4) then
                    local nmType = "APDU Type:    foreign frame";
                    spdu:add(buffer(pos,1),nmType);
                    info = info .. " | " .. nmType;
                else
                    local nmType = "APDU Type:    unknown";
                    spdu:add(buffer(pos,1),nmType);
                    info = info .. " | " .. nmType;
                end
                
            elseif(SPDU.SPDUtype == 2) then
                spdu:add(buffer(pos,1),"SPDUtype:     RESPONSE");
                local apdu = buffer(pos,2);
                info = info .. " | " .. "RESPONSE";
                
                if(apdu:bitfield(0, 2) == 0) then
                    local remain = buffer:len() - pos - 1 - 2;
                    local remainBuffer = buffer(pos+1,remain);
                    local id = apdu:bitfield(2, 6);
                    local nmType = "APDU Type:    generic application message #"..id;
                    spdu:add(buffer(pos,1),nmType);
                    spdu:add(remainBuffer, "APDU Data:    " .. remainBuffer:bytes():tohex());
                    info = info .. " | " .. nmType;
                elseif(apdu:bitfield(0, 2) == 2) then
                    local remain = buffer:len() - pos - 2 - 2;
                    local remainBuffer = buffer(pos+1,remain);
                    local id = apdu:bitfield(2, 14);
                    local nmType = "APDU Type:    network variable message IN #"..id;
                    spdu:add(buffer(pos,1),nmType);
                    spdu:add(remainBuffer, "APDU Data:    " .. remainBuffer:bytes():tohex());
                    info = info .. " | " .. nmType;
                elseif(apdu:bitfield(0, 2) == 3) then
                    local remain = buffer:len() - pos - 2 - 2;
                    local remainBuffer = buffer(pos+1,remain);
                    local id = apdu:bitfield(2, 14);
                    local nmType = "APDU Type:    network variable message OUT #"..id;
                    spdu:add(buffer(pos,1),nmType);
                    spdu:add(remainBuffer, "APDU Data:    " .. remainBuffer:bytes():tohex());
                    info = info .. " | " .. nmType;
                elseif(apdu:bitfield(0, 3) == 1) then
                    spdu:add(buffer(pos,1),"APDU Type:   NM/ND response");
                    pos = pos + 1;
                    local command = apdu:bitfield(3, 5);
                    
                    if(command == 1) then
                        local nmType = "NM Type:     Query ID";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 2) then
                        local nmType = "NM Type:     Respond to query";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 3) then
                        local nmType = "NM Type:     Update domain";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 4) then
                        local nmType = "NM Type:     Leave domain";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 4) then
                        local nmType = "NM Type:     Update key";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 7) then
                        local nmType = "NM Type:     Query address";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 8) then
                        local nmType = "NM Type:     Query network variable config";
                        spdu:add(buffer(pos,1),nmType);
                        
                        local priority = buffer(pos,1):bitfield(0, 1);
                        local direction = buffer(pos,1):bitfield(1, 1);
                        local selector = buffer(pos,2):bitfield(2, 14);
                        spdu:add(buffer(pos,1),"Response:      ");
                        spdu:add(buffer(pos,1),"  priority:      " .. priority);
                        spdu:add(buffer(pos,1),"  direction:     " .. direction);
                        spdu:add(buffer(pos,2),"  selector:      " .. selector);
                        pos = pos + 1;
                        pos = pos + 1;
                        local turnaround = buffer(pos,1):bitfield(0, 1);
                        local service = buffer(pos,1):bitfield(1, 2);
                        local authenticated = buffer(pos,1):bitfield(3, 1);
                        local index = buffer(pos,1):bitfield(4, 4);
                        
                        
                        spdu:add(buffer(pos,1),"  turnaround:    " .. turnaround);
                        spdu:add(buffer(pos,1),"  service:       " .. service);
                        spdu:add(buffer(pos,1),"  authenticated: " .. authenticated);
                        spdu:add(buffer(pos,1),"  index:         " .. index);
                        
                        pos = pos + 1;
                        info = info .. " | " .. nmType;
                    elseif(command == 9) then
                        local nmType = "NM Type:     Update group address";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 10) then
                        local nmType = "NM Type:     Query Domain";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 11) then
                        local nmType = "NM Type:     Update network variable config";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 12) then
                        local nmType = "NM Type:     Set node mode";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 13) then
                        local nmType = "NM Type:     Read memory";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 14) then
                        local nmType = "NM Type:     Write memory";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 15) then
                        local nmType = "NM Type:     Recalculate checksum";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 16) then
                        local nmType = "NM Type:     Install";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 17) then
                        local nmType = "NM Type:     Memory refresh";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 18) then
                        local nmType = "NM Type:     Query standard netowrk variable type";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    elseif(command == 19) then
                        local nmType = "NM Type:     Network variable fetch";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                        
                        spdu:add(buffer(pos,1),"NM Index:    " .. buffer(pos,1));
                        pos = pos + 1;
                        
                        local dataLen = buffer:len() - pos - 2;
                        local payload = "NM response: " .. buffer(pos,dataLen);
                        spdu:add(buffer(pos,1),payload);
                        info = info .. " | " .. payload;
                        pos = pos + dataLen;
                        
                    elseif(command == 20) then
                        local nmType = "NM Type:     Router mode";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    else
                        local nmType = "NM Type:     unknown (".. command ..")";
                        spdu:add(buffer(pos,1),nmType);
                        info = info .. " | " .. nmType;
                    end
                        
                elseif(apdu:bitfield(0, 4) == 5) then
                    local nmType = "APDU Type:    ND message";
                    spdu:add(buffer(pos,1),nmType);
                    info = info .. " | " .. nmType;
                elseif(apdu:bitfield(0, 4) == 4) then
                    local nmType = "APDU Type:    foreign frame";
                    spdu:add(buffer(pos,1),nmType);
                    info = info .. " | " .. nmType;
                elseif(apdu:bitfield(0, 3) == 0) then
                    local nmType = "APDU Type:     NM/ND response failed";
                    spdu:add(buffer(pos,1),nmType);
                    info = info .. " | " .. nmType;
                else
                    local nmType = "APDU Type:     unknown";
                    spdu:add(buffer(pos,1),nmType);
                    info = info .. " | " .. nmType;
                end
            elseif(SPDU.SPDUtype == 4) then
                local nmType = "SPDUtype:     REMINDER";
                info = info .. " | " .. "REMINDER";
                spdu:add(buffer(pos,1),nmType);
                info = info .. " | " .. nmType;
            elseif(SPDU.SPDUtype == 5) then
                local nmType = "SPDUtype:     REM/MSG";
                info = info .. " | " .. "REM/MSG";
                spdu:add(buffer(pos,1),nmType);
                info = info .. " | " .. nmType;
            else
                local nmType = "SPDUtype:     (invalid)";
                info = info .. " | " .. "(invalid)";
                spdu:add(buffer(pos,1),nmType);
                info = info .. " | " .. nmType;
            end
            
            pinfo.cols['info'] = info;
            
            
            
        elseif(NPDU.PDUFmt == 2) then
            local authpdu = npdu:add(mes_proto,buffer(),"PDUFmt: AuthPDU")
            authpdu:add(buffer(pos),"AuthPDU (not implemented)");
        elseif(NPDU.PDUFmt == 3) then
            local apdu = npdu:add(mes_proto,buffer(),"PDUFmt: APDU")
            APDU.Length = buffer:len() - pos - 2;
            
            apdu:add(buffer(pos,1),"Length:     " .. APDU.Length);
            
            if(APDU.Length > 2) then
                APDU.DestinType = buffer(pos,1);
                apdu:add(buffer(pos,1),"DestinType: " .. APDU.DestinType);
                if(APDU.DestinType:bitfield(0, 2) == 0) then
                    apdu:add(buffer(pos,1),"Content: Generic application message");
                elseif(APDU.DestinType:bitfield(0, 1) == 1) then
                    local nv = apdu:add(mes_proto,buffer(),"NV")
                
                    if(APDU.DestinType:bitfield(1, 1) == 0) then
                        nv:add(buffer(pos,1),"Content:  NV message, incoming");
                    else
                        nv:add(buffer(pos,1),"Content:  NV message, outgoing");
                    end
                    
                    NV.Selector = buffer(pos,2):bitfield(2, 14);
                    nv:add(buffer(pos,2),"Selector: "..NV.Selector);
                    pos = pos + 2;
                    
                    local remain = buffer:len()-pos-2;
                    if(remain > 0) then
                        NV.Value = buffer(pos, remain);  
                        nv:add(buffer(pos, remain),"Value:    "..NV.Value);
                    end
                    
                    
                    if(NV.Selector == 0x100) then
                        Time = {};
                        Time.Day = NV.Value:bitfield(24,8);
                        Time.Hours = NV.Value:bitfield(32,8);
                        Time.Minutes = NV.Value:bitfield(40,8);
                        info = info .. " | Date/Time: ".. Time.Hours .. ":" .. Time.Minutes .. " Day #" .. Time.Day;
                    elseif(NV.Selector == 0x0) then
                        temp = NV.Value:int();
                        info = info .. " | Aussen: ".. (temp/100.0) .. " C";
                    elseif(NV.Selector == 0x72) then
                        temp = NV.Value:int();
                        info = info .. " | Warmwasser Soll: ".. (temp/100.0) .. " C";
                    elseif(NV.Selector == 0x10) then
                        temp = NV.Value:int();
                        info = info .. " | Vorlauf Soll HK: ".. (temp/100.0) .. " C";
                    elseif(NV.Selector == 0x12) then
                        temp = NV.Value:int();
                        info = info .. " | Vorlauf Soll WW: ".. (temp/100.0) .. " C";
                    elseif(NV.Selector == 0x11) then
                        info = info .. " | 0x11:  ".. NV.Value .. "";
                    elseif(NV.Selector == 0x13) then
                        info = info .. " | 0x13:  ".. NV.Value .. "";
                    elseif(NV.Selector == 0x8A) then
                        info = info .. " | 0x8A:  ".. NV.Value .. "";
                    elseif(NV.Selector == 0x110) then
                        temp = NV.Value:int();
                        info = info .. " | Kessel: ".. (temp/100.0) .. " C";
                    elseif(NV.Selector == 0x101) then
                        temp = NV.Value:uint();
                        info = info .. " | Fehler: ".. temp .. "  |  !!!!!!!!!!!!!!!!!!!!!!!!";
                    else
                        info = info .. " | #### UNKNOWN ###";
                    end
                    
                    nv:add(buffer(pos, remain),info);
                    pos = pos + remain;
                    
                elseif(APDU.DestinType:bitfield(0, 3) == 3) then
                    pos = pos + 1;
                    local remain = buffer:len()-pos-2;
                    apdu:add(buffer(pos,remain),"Content:    network management");
                    if(remain > 0) then
                        NV.Value = buffer(pos, remain);  
                        nv:add(buffer(pos, remain),"Value:    "..NV.Value);
                    end
                    pos = pos + remain;
                elseif(APDU.DestinType:bitfield(0, 3) == 5) then
                    pos = pos + 1;
                    apdu:add(buffer(pos,remain),"Content:    diagnostic message");
                    if(remain > 0) then
                        NV.Value = buffer(pos, remain);  
                        nv:add(buffer(pos, remain),"Value:    "..NV.Value);
                    end
                    pos = pos + remain;
                elseif(APDU.DestinType:bitfield(0, 3) == 4) then
                    pos = pos + 1;
                    apdu:add(buffer(pos,remain),"Content:    foreign frame");
                    if(remain > 0) then
                        NV.Value = buffer(pos, remain);  
                        nv:add(buffer(pos, remain),"Value:    "..NV.Value);
                    end
                    pos = pos + remain;
                end
            end
            
        end
        PPDU.CRC = buffer(pos,2);
        ppdu:add(buffer(pos,2),"CRC:   " .. PPDU.CRC)
        pinfo.cols['info'] = info;
    end
end

-- load the udp.port table
udp_table = DissectorTable.get("udp.port")

-- register our protocol to handle udp port 3333
udp_table:add(3333,mes_proto)

