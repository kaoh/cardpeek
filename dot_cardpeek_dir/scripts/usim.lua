--
-- This file is part of Cardpeek, the smartcard reader utility.
--
-- Copyright 2021 by 'Karsten Ohme'
--
-- Cardpeek is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- Cardpeek is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with Cardpeek.  If not, see <http://www.gnu.org/licenses/>.
--
-- @name USIM
-- @description Analyzes USIM cards only (no 2G/SIM data)
-- @targets 0.8

require('lib.strict')
require('lib.apdu')
require("lib.tlv")

card.CLA = 0x00

function card.get_response(len)
    return card.send(bytes.new(8, card.CLA, 0xC0, 0x00, 0x00, len))
end

function card.gsm_select(file_path, return_what, length)
    local sw, resp = card.select(file_path, return_what, length)
    if bit.AND(sw, 0xFF00) == 0x6100 then
        sw, resp = card.get_response(bit.AND(sw, 0xFF))
    end
    return sw, resp
end

GSM_DEFAULT_ALPHABET = {
    "@", "£", "$", "¥", "è", "é", "ù", "ì", "ò", "Ç", "\\n", "Ø", "ø", "\\r", "Å", "å",
    "Δ", "_", "Φ", "Γ", "Λ", "Ω", "Π", "Ψ", "Σ", "Θ", "Ξ", "\\e", "Æ", "æ", "ß", "É",
    " ", "!", "\"", "#", "¤", "%", "&", "'", "(", ")", "*", "+", ",", "-", ".", "/",
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", ":", ";", "<", "=", ">", "?",
    "¡", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O",
    "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "Ä", "Ö", "Ñ", "Ü", "§",
    "¿", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o",
    "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "ä", "ö", "ñ", "ü", "à" }

BCD_EXTENDED = { "0", "1", "2", "3",
                 "4", "5", "6", "7",
                 "8", "9", "*", "#",
                 "-", "?", "!", "F" }

function GSM_bcd_swap(data, ignoreMsbF)
    local i, v
    local r = ""

    for i, v in data:ipairs() do
        local lsb = bit.AND(v, 0xF)
        local msb = bit.SHR(v, 4)

        if lsb == 0xF then
            break
        end
        r = r .. BCD_EXTENDED[1 + lsb]
        if msb == 0xF and not ignoreMsbF then
            break
        end
        r = r .. BCD_EXTENDED[1 + msb]
    end
    return r
end

function GSM_tostring(data)
    local r = ""
    local i, v

    for i, v in data:ipairs() do
        if v == 0xFF then
            return r
        end
        if v < 128 then
            r = r .. GSM_DEFAULT_ALPHABET[v + 1]
        else
            r = r .. '█'
        end
    end
    return r
end

function GSM_decode_udh(data)
    if data[0] == 5 and data[1] == 0 then
        return string.format("(part %d/%d in %d)", data[5], data[4], data[3])
    elseif data[0] == 6 and data[1] == 8 then
        return string.format("(part %d/%d in %d)", data[6], data[5], data[3] * 256 + data[4])
    else
        return "(undexpected UDH)"
    end
end

function GSM_decode_default_alphabet(data, skip)
    local text = ""
    local char
    local back_char = 0
    local pos
    local skip = skip or 0

    if data == nil then
        return ""
    end

    for pos = 0, #data - 1 do
        shifted = (pos % 7)

        char = bit.AND(bit.SHL(data:get(pos), shifted), 0x7F) + back_char
        back_char = bit.SHR(data:get(pos), 7 - shifted)

        if skip == 0 then
            text = text .. GSM_DEFAULT_ALPHABET[char + 1]
        else
            skip = skip - 1
        end

        if shifted == 6 then
            if pos == #data - 1 then
                if back_char == 0x0D then
                    break
                end
                -- This should not be done, as it may
                -- accidentally cut trailing '@', but
                -- most phones fill 7 spare bits by
                -- zeroes instead of 0x0D and also cut
                -- trailing '@'
                if back_char == 0x00 then
                    break
                end
            end

            if skip == 0 then
                text = text .. GSM_DEFAULT_ALPHABET[back_char + 1]
            else
                skip = skip - 1
            end

            back_char = 0
        end
    end
    return text
end

function GSM_decode_ucs2(data, skip)
    local text = ""
    local ucs2
    local utf8 = ""
    local pos
    local skip = skip or 0

    if data == nil then
        return ""
    end

    if skip > 0 then
        data = data:sub(skip)
    end

    for pos = 0, (#data / 2) - 1 do
        ucs2 = bit.SHL(data:get(pos * 2), 8) + data:get(pos * 2 + 1)
        if ucs2 < 0x80 then
            utf8 = string.format('%c', ucs2)
        end
        if ucs2 >= 0x80 and ucs2 < 0x800 then
            utf8 = string.format('%c%c', bit.OR(bit.SHR(ucs2, 6), 0xC0), bit.OR(bit.AND(ucs2, 0x3F), 0x80))
        end
        if ucs2 >= 0x800 and ucs2 < 0xFFFF then
            if not (ucs2 >= 0xD800 and ucs2 <= 0xDFFF) then
                utf8 = string.format('%c%c%c', bit.OR(bit.SHR(ucs2, 12), 0xE0), bit.OR(bit.AND(bit.SHR(ucs2, 6), 0x3F), 0x80), bit.OR(bit.AND(ucs2, 0x3F), 0x80))
            end
        end
        text = text .. utf8
    end
    return text
end

-------------------------------------------------------------------------

function GSM_byte_map(node, data, map)

    local ret = node:set_attribute("alt", map[bytes.tonumber(data)])
    return ret
end

function USIM_app_dir(node, data)
    local t, v
    local aid
    t, v = asn1.split(data)
    if t ~= 0x61 then
        log.print(log.ERROR, "Invalid application directory.")
        return
    end
    t, v = asn1.split(v)
    if t ~= 0x4F then
        log.print(log.ERROR, "Invalid application directory.")
        return
    end
    aid = tostring(v)
    log.print(log.INFO, "AID: " .. aid)
    -- check if USIM ADF
    if string.find(aid, "A0000000871002", 1, false) then
        USIM_ADF_MAP[2] = aid
    end
end

function USIM_ICCID(node, data)
    return node:set_attribute("alt", "(89)" .. GSM_bcd_swap(data, false):sub(3, -1))
end

function USIM_IMSI(node, data)
    return node:set_attribute("alt", GSM_bcd_swap(data, false):sub(4, -1))
end

function USIM_decode_PLMN(encoded)
    local mcc12_mcc3Mnc3_mnc12
    mcc12_mcc3Mnc3_mnc12 = GSM_bcd_swap(encoded, true);
    return string.sub(mcc12_mcc3Mnc3_mnc12, 1, 2) .. string.sub(mcc12_mcc3Mnc3_mnc12, 3, 3) ..
            string.sub(mcc12_mcc3Mnc3_mnc12, 5, 6) .. string.sub(mcc12_mcc3Mnc3_mnc12, 4, 4)
end

ACCESS_MODE = {
    [0] = "DF Delete Child, EF Read Binary, EF Read Record, EF Search Binary, EF Search Record",
    [1] = "DF Create EF, EF Update Binary, EF Update Record, EF Erase Binary, EF Erase Record",
    [2] = "DF Create DF, EF Write Binary, EF Write Record, EF Append Record",
    [3] = "DF Deactivate, EF Deactivate",
    [4] = "DF Activate, EF Activate",
    [5] = "DF Terminate Card Usage, DF Terminate, EF Terminate",
    [6] = "DF Delete Self, EF Delete",
    [7] = "Proprietary"
}

SECURITY_CONDITION_TYPE = {
    [0xAF] = "And",
    [0xA0] = "Or",
    [0xA7] = "Not",
    [0x90] = "Always",
    [0x97] = "Never",
    [0x9E] = "Security condition",
    [0xA4] = "Control Reference Template Authentication"
}

CONTROL_REFERENCE_TEMPLATE = {
    [0x80] = "Cryptographic mechanism",
    [0x81] = "File reference",
    [0x82] = "DF name",
    [0x83] = "Data or secret or public key reference",
    [0x84] = "Session or private key reference",
    [0xA3] = "Key usage",
    [0x94] = "Challenge or data element for deriving a key",
    [0x95] = "Usage qualifier"
}

USAGE_QUALIFIER = {
    [0] = "Not used",
    [0x80] = "Verification",
    [0x40] = "Computation",
    [0x20] = "Secure messaging response data",
    [0x10] = "Secure messaging command data",
    [0x08] = "Password",
    [0x04] = "Biometry"
}

USIM_ACCESS_TECHNOLOGIES_E_UTRAN = {
    [0] = "E-UTRAN not selected",
    [1] = "E-UTRAN not selected",
    [2] = "E-UTRAN not selected",
    [3] = "E-UTRAN not selected",
    [4] = "E-UTRAN in WB-S1 mode and NB-S1 mode",
    [5] = "E-UTRAN in NB-S1 mode only",
    [6] = "E-UTRAN in WB-S1 mode only",
    [7] = "E-UTRAN in WB-S1 mode and NB-S1 mode"
}

USIM_ACCESS_TECHNOLOGIES_GSM = {
    [0] = "GSM and EC-GSM-IoT not selected",
    [0x04] = "GSM and EC-GSM-IoT not selected",
    [0x08] = "GSM and EC-GSM-IoT not selected",
    [0x0C] = "GSM and EC-GSM-IoT not selected",
    [0x80] = "GSM and EC-GSM-IoT",
    [0x84] = "GSM without EC-GSM-IoT",
    [0x88] = "EC-GSM-IoT only",
    [0x8C] = "GSM and EC-GSM-IoT"
}

function USIM_PLMN(node, data)
    local plmn
    local r = ""
    for i = 0, #data - 1, 3 do
        plmn = bytes.sub(data, i, i + 3)
        if plmn[0] == 0xFF then
            break
        end
        r = r .. "MCCMNC " .. USIM_decode_PLMN(plmn)
        if i ~= #data and data[i + 4] ~= 0xFF then
            r = r .. ", "
        end
    end
    return node:set_attribute("alt", r)
end

function USIM_AccessRule(node, data)
    local securityCondition, usageQualifier, reference, accessModes
    local r = ""
    local remaining = data
    local t, v
    r = r .. tostring(data) .. "\n"
    while remaining ~= nil do
        t, v, remaining = asn1.split(remaining)
        if t ~= 0x80 then
            goto continue
        end
        accessModes = {}
        usageQualifier = nil
        reference = nil
        for i = 0, 7, 1 do
            if bit.AND(bit.SHL(1, i), v:get(0)) > 0 then
                table.insert(accessModes, ACCESS_MODE[i])
            end
        end
        t, v, remaining = asn1.split(remaining)
        securityCondition = SECURITY_CONDITION_TYPE[t]
        if securityCondition == nil then
            goto continue
        end
        if t == 0xA4 then
            local crt = v
            while crt ~= nil do
                t, v, crt = asn1.split(crt)
                if t == 0x83 then
                    reference = v:get(0)
                end
                if t == 0x95 then
                    usageQualifier = USAGE_QUALIFIER[v:get(0)]
                end
            end
        end
        r = r .. "Access mode: "
        for _, value1 in ipairs(accessModes) do
            r = r .. value1 .. "\n"
        end
        r = r .. "Security condition: " .. securityCondition .. "\n"
        if reference ~= nil then
            r = r .. "Reference: " .. reference .. "\n"
        end
        if usageQualifier ~= nil then
            r = r .. "Usage qualifier: " .. usageQualifier .. "\n"
        end
        r = r .. "\n"
        :: continue ::
    end
    return node:set_attribute("alt", r)
end

function USIM_PLMNwAcT(node, data)
    local plmn, plmn_wact, act1, act2, technologies
    local plmns = {}
    local r = ""
    for i = 0, #data - 1, 5 do
        plmn_wact = bytes.sub(data, i, i + 4)
        if plmn_wact[0] == 0xFF then
            break
        end
        plmn = USIM_decode_PLMN(plmn_wact)
        act1 = bytes.tonumber(bytes.sub(plmn_wact, 3, 3))
        act2 = bytes.tonumber(bytes.sub(plmn_wact, 4, 4))
        technologies = {}
        if bit.AND(act1, 0x80) > 0 then
            table.insert(technologies, "UTRAN")
        end
        if bit.AND(act1, 0x40) > 0 then
            table.insert(technologies, USIM_ACCESS_TECHNOLOGIES_E_UTRAN[bit.SHR(bit.AND(act1, 0x70), 4)])
        end
        if bit.AND(act1, 0x08) > 0 then
            table.insert(technologies, "NG-RAN")
        end
        if bit.AND(act2, 0x80) > 0 then
            table.insert(technologies, USIM_ACCESS_TECHNOLOGIES_GSM[bit.AND(act1, 0x8C)])
        end
        if bit.AND(act2, 0x40) > 0 then
            table.insert(technologies, "GSM COMPACT")
        end
        if bit.AND(act2, 0x20) > 0 then
            table.insert(technologies, "cdma2000 HRPD")
        end
        if bit.AND(act2, 0x10) > 0 then
            table.insert(technologies, "cdma2000 1xRTT")
        end
        table.insert(plmns, { plmn, technologies })
    end
    for i1, value1 in ipairs(plmns) do
        r = r .. "MCCMNC: " .. value1[1] .. ", AcT: "
        for i2, value2 in ipairs(value1[2]) do
            r = r .. value2
            if i2 ~= #value1[2] then
                r = r .. ", "
            end
        end
        if i1 ~= #plmns then
            r = r .. "\n"
        end
    end
    return node:set_attribute("alt", r)
end

function USIM_SPN(node, data)
    return node:set_attribute("alt", GSM_tostring(bytes.sub(data, 1)))
end

function USIM_MSISDN(node, data)
    local alpha_len = #data - 14
    local r = ""
    if data:get(0) == 0xFF then
        return node:set_attribute("alt", "(empty)")
    end
    if alpha_len then
        r = GSM_tostring(bytes.sub(data, 0, alpha_len - 1))
    end
    r = r .. ": " .. GSM_bcd_swap(bytes.sub(data, alpha_len + 2, alpha_len + 12), false)
    return node:set_attribute("alt", r)
end

function USIM_OPL(node, data)
    plmn = bytes.sub(data, 0, 2)
    local r = ""
    r = r .. "MCCMNC " .. USIM_decode_PLMN(plmn)
    r = r .. ", LAC/TAC " .. tostring(bytes.sub(data, 3, 6)) .. ", Rec # " .. bytes.tonumber(bytes.sub(data, 7, 7))
    return node:set_attribute("alt", r)
end


function GSM_SMS_decode_ucs2(node, data)
    local text = ""
    local ucs2
    local utf8
    local pos

    for pos = 0, (#data / 2) - 1 do
        ucs2 = bit.SHL(data:get(pos * 2), 8) + data:get(pos * 2 + 1)
        if ucs2 < 0x80 then
            utf8 = string.format('%c', ucs2)
        end
        if ucs2 >= 0x80 and ucs2 < 0x800 then
            utf8 = string.format('%c%c', bit.OR(bit.SHR(ucs2, 6), 0xC0), bit.OR(bit.AND(ucs2, 0x3F), 0x80))
        end
        if ucs2 >= 0x800 and ucs2 < 0xFFFF then
            if not (ucs2 >= 0xD800 and ucs2 <= 0xDFFF) then
                utf8 = string.format('%c%c%c', bit.OR(bit.SHR(ucs2, 12), 0xE0), bit.OR(bit.AND(bit.SHR(ucs2, 6), 0x3F), 0x80), bit.OR(bit.AND(ucs2, 0x3F), 0x80))
            end
        end
        text = text .. utf8
    end
    return node:set_attribute("alt", text)
end

function GSM_SMS_TPDCS(node, data)
    local text
    local encoding = 0x100
    local compressed = 0x100

    if bit.AND(data:get(0), 0xC0) then
        encoding = bit.AND(data:get(0), 0x0C)
        compressed = bit.AND(data:get(0), 0x20)
    end
    if encoding ~= 0x100 then
        if encoding == 0x00 then
            text = 'encoding=GSM_DEFAULT_ALPHABET'
        elseif encoding == 0x08 then
            text = 'encoding=UNICODE'
        elseif encoding == 0x0C then
            text = 'encoding=RESERVED'
        else
            text = string.format('encoding=UNKNOWN_%X', encoding)
        end
        if compressed ~= 0x100 then
            if compressed ~= 0x00 then
                text = text .. ',COMPRESSED'
            end
        end
        return node:set_attribute("alt", text)
        -- else TODO
    end
end

TON = {
    [0] = "Unknown",
    [1] = "International number",
    [2] = "National number",
    [3] = "Network specific number",
    [4] = "Subscriber number",
    [5] = "Alphanumeric",
    [6] = "Abbreviated number",
    [7] = "Reserved for extension"
}

NPI = {
    [0] = "Unknown",
    [1] = "ISDN/telephone numbering plan (E.164/E.163)",
    [3] = "Data numbering plan (X.121)",
    [4] = "Telex numbering plan",
    [5] = "Service Centre Specific plan",
    [6] = "Service Centre Specific plan",
    [8] = "National numbering plan",
    [9] = "Private numbering plan",
    [10] = "ERMES numbering plan (ETSI DE/PS 3 01 3)",
    [15] = "Reserved for extension"
}

function GSM_type_of_address(node, data)
    local b = data[0]
    local r1 = TON[bit.AND(bit.SHR(b, 4), 7)]
    local r2 = NPI[bit.AND(b, 15)]
    if r2 ~= nil then
        r1 = r1 .. ", " .. r2
    end
    node:set_attribute("alt", r1)
end

function GSM_SMS_deliver_header(node, data)
    local b = data[0]
    local r = "SMS-DELIVER"
    if bit.AND(b, 4) == 4 then
        r = r .. ", TP-More-Message-to-Send"
    end
    if bit.AND(b, 8) == 8 then
        r = r .. ", TP-Loop-Prevention"
    end
    if bit.AND(b, 32) == 32 then
        r = r .. ", TP-Status-Report-Indicator"
    end
    if bit.AND(b, 64) == 64 then
        r = r .. ", TP-User-Data-Header-Indicator"
    end
    if bit.AND(b, 128) == 128 then
        r = r .. ", TP-Reply-Path"
    end
    node:set_attribute("alt", r)
end

function GSM_number(node, data)
    local bcd = GSM_bcd_swap(data, false)

    if (bcd[#bcd] == 'F') then
        node:set_attribute("alt", string.sub(bcd, 1, -1))
    else
        node:set_attribute("alt", bcd)
    end
end

function GSM_byte(node, data)
    node:set_attribute("alt", data:get(0))
end

GSM_MONTHS = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
               "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" }
GSM_QUARTER = { "00", "15", "30", "45" }

function GSM_timestamp(node, data)
    local bcd = data:convert(4)
    local tz = bcd:get(13) * 10 + bcd:get(12)
    local year = bcd:get(1) * 10 + bcd:get(0)

    if year > 90 then
        year = 1900 + year
    else
        year = 2000 + year
    end

    node:set_attribute("alt", string.format("%i%i:%i%i:%i%i, %i%i %s %i [+%i:%s]",
            bcd:get(7), bcd:get(6),
            bcd:get(9), bcd:get(8),
            bcd:get(11), bcd:get(10),
            bcd:get(5), bcd:get(4),
            GSM_MONTHS[bcd:get(3) * 10 + bcd:get(2)],
            year,
            math.floor(tz / 4), GSM_QUARTER[1 + tz % 4]));

end

function create_sub_node(node, data, label, pos, len, func)
    local subnode
    local edata = bytes.sub(data, pos, pos + len - 1)

    if edata == nil then
        edata = bytes.new(8)
    end

    subnode = node:append { classname = "item", label = label, size = #edata, val = edata }
    if func then
        func(subnode, edata)
    end
end

function GSM_SMS_text(node, data, encoding, compressed, udhi)
    local text
    local real_len

end

function USIM_SMS(node, data)
    local subnode
    local pos
    local encoding = 0x100
    local compressed = 0x100
    local tpdcs
    local udhi = false
    local text
    local text_encoded
    local text_len

    create_sub_node(node, data, "status", 0, 1)
    pos = 1
    if data:get(0) ~= 0 then
        create_sub_node(node, data, "Length of SMSC information", pos, 1, GSM_byte)
        create_sub_node(node, data, "Type of address", pos + 1, 1)
        create_sub_node(node, data, "Service center number", pos + 2, data:get(pos) - 1, GSM_number)
        pos = pos + data:get(pos) + 1
        create_sub_node(node, data, "First octet SMS deliver message", pos, 1, GSM_SMS_deliver_header)
        if bit.AND(data:get(pos), 64) == 64 then
            udhi = true
        end
        pos = pos + 1
        create_sub_node(node, data, "Length of address", pos, 1, GSM_byte)
        create_sub_node(node, data, "Type of address", pos + 1, 1, GSM_type_of_address)
        create_sub_node(node, data, "Sender number" .. " " .. tostring(data:get(pos)), pos + 2, math.floor((data:get(pos) + 1) / 2), GSM_number)
        pos = pos + math.floor((data:get(pos) + 1) / 2) + 2
        create_sub_node(node, data, "TP-PID", pos, 1)
        if bit.AND(data:get(pos + 1), 0xC0) then
            encoding = bit.AND(data:get(pos + 1), 0x0C)
            compressed = bit.AND(data:get(pos + 1), 0x20)
            -- else TODO
        end
        create_sub_node(node, data, "TP-DCS", pos + 1, 1, GSM_SMS_TPDCS)
        create_sub_node(node, data, "TP-SCTS", pos + 2, 7, GSM_timestamp)
        pos = pos + 9
        create_sub_node(node, data, "Length of SMS", pos, 1, GSM_byte)

        if encoding == 0 and compressed == 0 then
            text_len = math.floor((data:get(pos) * 7 + 7) / 8)
            text_encoded = data:sub(pos + 1, pos + text_len)
            if udhi then
                text = GSM_decode_default_alphabet(text_encoded, math.floor(((text_encoded[0] + 1) * 8 + 6) / 7))
            else
                text = GSM_decode_default_alphabet(text_encoded)
            end
        elseif encoding == 8 and compressed == 0 then
            text_len = data:get(pos)
            text_encoded = data:sub(pos + 1, pos + text_len)
            if udhi then
                text = GSM_decode_ucs2(text_encoded, text_encoded[0] + 1)
            else
                text = GSM_decode_ucs2(text_encoded)
            end
        else
            text_len = data:get(pos)
            text_encoded = data:sub(pos + 1, pos + text_len)
            text = nil
        end
        subnode = node:append { classname = "item", label = "Text of SMS", size = text_len, val = text_encoded, alt = text }
        if udhi then
            subnode:append { classname = "item", label = "Multipart SMS", val = text_encoded:sub(0, text_encoded[0]), alt = GSM_decode_udh(text_encoded) }
        end
    end
end


--[[
	GSM_MAP allows to map out the content of a GSM SIM card into a set of nodes diplayed in the cardpeek
	interface.

	Each entry in GSM_MAP reperesents a node and is composed of 4 parts:
		1. a "classname" (the icon used in cardpeek)
		2. an "id" (the id of the node)
		3. a "label" for the node.
		4. an action to undertake, which itself can take 3 types of values:
			(a) a function name representing a function that will be called to futher process the data.
			(b) an array of GSM_MAP entries, mapping out a sub-directory.
			(c) nil, meaning that we do nothing except show raw data.

	The function described in 4(a) takes two parameters: the (tQuery) node in the cardpeek interface, and the 
	data itself, represented as a bytestring. The function can therefore create sub-nodes and/or create 
	interpretation of the data (by calling the alt() function on the node). 

--]]

USIM_MAP = { "folder", "3F00", "MF", {
    { "file", "2F00", "Application directory", USIM_app_dir },
    { "file", "2F05", "Preferred languages", nil },
    { "file", "2F06", "Access rule reference", USIM_AccessRule },
    { "file", "2FE2", "ICCID", USIM_ICCID },
    { "folder", "7F10", "TELECOM", {
        { "file", "6F06", "Access rule reference", USIM_AccessRule },
        { "file", "6F3A", "Abbreviated dialling numbers", USIM_MSISDN },
        { "file", "6F3B", "Fixed dialing numbers", USIM_MSISDN },
        { "file", "6F3C", "Short messages", USIM_SMS },
        { "file", "6F3D", "Capability configuration parameters", nil },
        { "file", "6F40", "MSISDN", USIM_MSISDN },
        { "file", "6F42", "SMS parameters", nil },
        { "file", "6F43", "SMS status", nil },
        { "file", "6F44", "LND", USIM_MSISDN },
        { "file", "6F47", "Short message status report", nil },
        { "file", "6F49", "Service dialing numbers", USIM_MSISDN },
        { "file", "6F4A", "Extension 1", nil },
        { "file", "6F4B", "Extension 2", nil },
        { "file", "6F4C", "Extension 3", nil },
        { "file", "6F4D", "Barred dialing numbers", nil },
        { "file", "6F4E", "Extension 5", nil },
        { "file", "6F4F", "Extended Capability Configuration Parameter", nil },
        { "file", "6F53", "GPRS location", nil },
        { "file", "6F54", "SetUp menu elements", nil },
        { "file", "6FE0", "In case of emergency - dialing number", nil },
        { "file", "6FE1", "In case of emergency - free format", nil },
        { "file", "6FE5", "Public service identity of the SM-SC", nil },

    }
    },
    { "folder", "7F20", "GSM", {
        { "file", "6F05", "Language indication", nil },
        { "file", "6F07", "IMSI", USIM_IMSI },
        { "file", "6F20", "Ciphering key Kc", nil },
        { "file", "6F30", "PLMN selector", USIM_PLMN },
        { "file", "6F31", "Higher priority PLMN search", nil },
        { "file", "6F37", "ACM maximum value", nil },
        { "file", "6F38", "Sim service table", nil },
        { "file", "6F39", "Accumulated call meter", nil },
        { "file", "6F3E", "Group identifier 1", nil },
        { "file", "6F3F", "Groupe identifier 2", nil },
        { "file", "6F41", "PUCT", nil },
        { "file", "6F45", "CBMI", nil },
        { "file", "6F46", "Service provider name", USIM_SPN },
        { "file", "6F74", "BCCH", nil },
        { "file", "6F78", "Access control class", nil },
        { "file", "6F7B", "Forbidden PLMNs", USIM_PLMN },
        { "file", "6F7E", "Location information", nil },
        { "file", "6FAD", "Administrative data", nil },
        { "file", "6FAE", "Phase identification", nil },
    }
    },
}
}

USIM_ADF_MAP = {
    "folder", nil, "USIM ADF", {
        { "file", "6F05", "Language Indication", nil },
        { "file", "6F07", "IMSI", USIM_IMSI },
        { "file", "6F08", "Ciphering and Integrity Keys", nil },
        { "file", "6F09", "Ciphering and Integrity Keys for Packet Switched domain", nil },
        { "file", "6F60", "User controlled PLMN selector with Access Technology", USIM_PLMNwAcT },
        { "file", "6F31", "Higher Priority PLMN search period", nil },
        { "file", "6F37", "ACM maximum value", nil },
        { "file", "6F38", "USIM Service Table", nil },
        { "file", "6F39", "Accumulated Call Meter", nil },
        { "file", "6F3E", "Group Identifier Level 1", nil },
        { "file", "6F3F", "Group Identifier Level 2", nil },
        { "file", "6F46", "Service Provider Name", USIM_SPN },
        { "file", "6F41", "Price per Unit and Currency Table", nil },
        { "file", "6F45", "Cell Broadcast Message identifier selection", nil },
        { "file", "6F78", "Access Control Class", nil },
        { "file", "6F7B", "Forbidden PLMNs", USIM_PLMN },
        { "file", "6F7E", "Location Information", nil },
        { "file", "6FAD", "Administrative Data", nil },
        { "file", "6F48", "Cell Broadcast Message Identifier for Data Download", nil },
        { "file", "6FB7", "Emergency Call Codes", nil },
        { "file", "6F50", "Cell Broadcast Message Identifier Range selection", nil },
        { "file", "6F73", "Packet Switched location information", nil },
        { "file", "6F3B", "Fixed Dialling Numbers", USIM_MSISDN },
        { "file", "6F3C", "Short messages", USIM_SMS },
        { "file", "6F40", "MSISDN", USIM_MSISDN },
        { "file", "6F42", "Short message service parameters", nil },
        { "file", "6F43", "SMS status", nil },
        { "file", "6F49", "Service Dialling Numbers", USIM_MSISDN },
        { "file", "6F4B", "Extension2", nil },
        { "file", "6F4C", "Extension3", nil },
        { "file", "6F47", "Short message status reports", nil },
        { "file", "6F80", "Incoming Call Information", nil },
        { "file", "6F81", "Outgoing Call Information", nil },
        { "file", "6F82", "Incoming Call Timer", nil },
        { "file", "6F83", "Outgoing Call Timer", nil },
        { "file", "6F4E", "Extension5", nil },
        { "file", "6F4F", "Capability Configuration Parameters 2", nil },
        { "file", "6FB5", "enhanced Multi Level Precedence and Pre-emption", nil },
        { "file", "6FB6", "Automatic Answer for eMLPP Service", nil },
        { "file", "6FC3", "Key for hidden phone book entries", nil },
        { "file", "6F4D", "Barred Dialling Numbers", USIM_MSISDN },
        { "file", "6F55", "Extension4", nil },
        { "file", "6F58", "Comparison Method Information", nil },
        { "file", "6F56", "Enabled Services Table", nil },
        { "file", "6F57", "Access Point Name Control List", nil },
        { "file", "6F2C", "Depersonalisation Control Keys", nil },
        { "file", "6F32", "Co-operative Network List", nil },
        { "file", "6F5B", "Initialisation values for Hyperframe number", nil },
        { "file", "6F5C", "Maximum value of START", nil },
        { "file", "6F61", "Operator controlled PLMN selector with Access Technology", USIM_PLMNwAcT },
        { "file", "6F62", "HPLMN selector with Access Technology", USIM_PLMNwAcT },
        { "file", "6F06", "Access Rule Reference", USIM_AccessRule },
        { "file", "6FC4", "Network Parameters", nil },
        { "file", "6FC5", "PLMN Network Name", nil },
        { "file", "6FC6", "Operator PLMN List", USIM_OPL },
        { "file", "6FC7", "Mailbox Dialling Numbers", USIM_MSISDN },
        { "file", "6FC8", "Extension6", nil },
        { "file", "6FC9", "Mailbox Identifier", nil },
        { "file", "6FCA", "Message Waiting Indication Status", nil },
        { "file", "6FCB", "Call Forwarding Indication Status", nil },
        { "file", "6FCC", "Extension7", nil },
        { "file", "6FCD", "Service Provider Display Information", nil },
        { "file", "6FCE", "MMS Notification", nil },
        { "file", "6FCF", "Extension 8", nil },
        { "file", "6FD0", "MMS Issuer Connectivity Parameters", nil },
        { "file", "6FD1", "MMS User Preferences", nil },
        { "file", "6FD2", "MMS User Connectivity Parameters", nil },
        { "file", "6FD3", "Network's Indication of Alerting", nil },
        { "file", "6FB1", "Voice Group Call Service", nil },
        { "file", "6FB2", "Voice Group Call Service Status", nil },
        { "file", "6FB3", "Voice Broadcast Service", nil },
        { "file", "6FB4", "Voice Broadcast Service Status", nil },
        { "file", "6FD4", "Voice Group Call Service Ciphering Algorithm", nil },
        { "file", "6FD5", "Voice Broadcast Service Ciphering Algorithm", nil },
        { "file", "6FD6", "GBA Bootstrapping parameters", nil },
        { "file", "6FD7", "MBMS Service Keys List", nil },
        { "file", "6FD8", "MBMS User Key", nil },
        { "file", "6FDA", "GBA NAF List", nil },
        { "file", "6FD9", "Equivalent HPLMN", USIM_PLMN },
        { "file", "6FDB", "Equivalent HPLMN Presentation Indication", nil },
        { "file", "6FDC", "Last RPLMN Selection Indication", nil },
        { "file", "6FDD", "NAF Key Centre Address", nil },
        { "file", "6FDE", "Service Provider Name Icon", nil },
        { "file", "6FDF", "PLMN Network Name Icon", nil },
        { "file", "6FE2", "Network Connectivity Parameters for USIM IP connections", nil },
        { "file", "6FE3", "EPS location information", nil },
        { "file", "6FE4", "EPS NAS Security Context", nil },
        { "file", "6FE6", "USAT Facility Control", nil },
        { "file", "6FE8", "Non Access Stratum Configuration", nil },
        { "file", "6FE7", "UICC IARI", nil },
        { "file", "6FEC", "Public Warning System", nil },
        { "file", "6FED", "Fixed Dialling Numbers URI", nil },
        { "file", "6FEE", "Barred Dialling Numbers URI", nil },
        { "file", "6FEF", "Service Dialling Numbers URI", nil },
        { "file", "6FF0", "IMEI(SV) White Lists", nil },
        { "file", "6FF1", "IMEI(SV) Pairing Status", nil },
        { "file", "6FF2", "IMEI(SV) of Pairing Device", nil },
        { "file", "6FF3", "Home ePDG Identifier", nil },
        { "file", "6FF4", "ePDG Selection Information", nil },
        { "file", "6FF5", "Emergency ePDG Identifier", nil },
        { "file", "6FF6", "ePDG Selection Information for Emergency Services", nil },
        { "file", "6FF7", "From Preferred", nil },
        { "file", "6FF8", "IMS Configuration Data", nil },
        { "file", "6FF9", "3GPP PS Data Off", nil },
        { "file", "6FFA", "3GPP PS Data Off Service List", nil },
        { "file", "6FFE", "EARFCN list for MTC/NB-IOT UEs", nil },
        { "file", "6FFF", "5GS 3GPP location information", nil },
        { "file", "6F01", "5G authentication keys", nil },
        { "file", "6F02", "5GS 3GPP Access NAS Security Context", nil },
        { "file", "6F03", "5GS non-3GPP Access NAS Security Context", nil },
        { "file", "6F04", "Subscription Concealed Identifier Calculation Information EF", nil },
        { "file", "6F05", "UAC Access Identities Configuration", nil },
        { "file", "6F05", "Steering of UE in VPLMN", nil },
    }
}

USIM_FILE_TYPES = {
    [0] = "Working EF",
    [1] = "Internal EF",
    [2] = "RFU",
    [3] = "RFU",
    [4] = "RFU",
    [5] = "RFU",
    [6] = "RFU",
    [7] = "DF or ADF"
}

USIM_EF_STRUCTURE = {
    [0] = "No information",
    [1] = "Transparent structure",
    [2] = "Linear fixed structure",
    [3] = "RFU",
    [4] = "RFU",
    [5] = "RFU",
    [6] = "Cyclic structure",
    [7] = "RFU"
}

function read_file_descriptor_byte(fdb)
    local shareable
    if bit.AND(fdb, 0x40) then
        shareable = true
    end
    return shareable, bit.SHR(bit.AND(fdb, 0x38), 3), bit.AND(fdb, 0x07)
end

function to_short(b, offset)
    return bytes.tonumber(bytes.sub(b, offset, offset + 1))
end

function usim_map_descriptor(node, data)
    local child
    local t, v
    local fd
    local item
    local shareable, file_type, ef_structure
    local num_records, record_length
    local file_size
    node = node:append { classname = "header", label = "answer to select", size = #data, val = data }

    t, v = asn1.split(data)
    if t ~= 0x62 then
        log.print(log.WARN, "Invalid select response")
        return
    end
    -- file descriptor
    t, fd, v = asn1.split(v)
    if t ~= 0x82 then
        log.print(log.WARN, "Invalid file descriptor")
        return
    end
    child = node:append { classname = "item", label = "File descriptor", size = #fd, val = fd }
    shareable, file_type, ef_structure = read_file_descriptor_byte(fd[0])
    if #fd == 2 then
        child:set_attribute("alt", string.format("Shareable: %s, file type: %s, structure: %s", tostring(shareable), USIM_FILE_TYPES[file_type], USIM_EF_STRUCTURE[ef_structure]))
    elseif #fd == 5 then
        record_length = to_short(fd, 2)
        num_records = fd[4]
        child:set_attribute("alt", string.format("Shareable: %s, file type: %s, structure: %s, record length: %d, num records: %d", tostring(shareable), USIM_FILE_TYPES[file_type], USIM_EF_STRUCTURE[ef_structure], record_length, num_records))
    end
    repeat
        t, item, v = asn1.split(v)
        if t == 0x83 then
            child = node:append { classname = "item", label = "File ID", size = #item, val = item }
        end
        if t == 0x84 then
            child = node:append { classname = "item", label = "AID", size = #item, val = item }
        end
        if t == 0xA5 then
            child = node:append { classname = "item", label = "Prop. information", size = #item, val = item }
        end
        if t == 0x8A then
            child = node:append { classname = "item", label = "Life cycle status", size = #item, val = item }
        end
        if t == 0x8B or t == 0x8C or t == 0xAB then
            child = node:append { classname = "item", label = "Security attributes", size = #item, val = item }
        end
        if t == 0x80 then
            file_size = to_short(item, 0)
            child = node:append { classname = "item", label = "File size", size = #item, val = file_size }
            child:set_attribute("alt", string.format("File size: %d", file_size))
        end
        if t == 0x81 then
            child = node:append { classname = "item", label = "Total file size", size = #item, val = item }
            child:set_attribute("alt", string.format("Total file size: %d", to_short(item, 0)))
        end
        if t == 0xC6 then
            child = node:append { classname = "item", label = "PIN Status Template DO", size = #item, val = item }
        end
        if t == 0x88 then
            child = node:append { classname = "item", label = "SFI", size = #item, val = item }
        end
    until v == nil
    return file_type, ef_structure, record_length, num_records, file_size
end

function usim_read_content_binary(node, fsize, alt)
    local pos = 0
    local try_read
    local sw, resp
    local data = bytes.new(8)

    while fsize > 0 do
        if fsize > 128 then
            try_read = 128
        else
            try_read = fsize
        end
        sw, resp = card.read_binary('.', pos, try_read)
        if sw ~= 0x9000 then
            return false
        end
        data = bytes.concat(data, resp)
        pos = pos + try_read
        fsize = fsize - try_read
    end

    node = node:append { classname = "body", label = "data", size = #data, val = data }
    if alt then
        alt(node, data)
    end
    return true
end

function usim_read_content_record(node, fsize, rec_len, alt)
    local rec_count
    local rec_num
    local sw, resp
    local record

    if rec_len == nil or rec_len == 0 then
        return false
    end
    rec_count = fsize / rec_len

    for rec_num = 1, rec_count do
        sw, resp = card.read_record('.', rec_num, rec_len)
        if sw ~= 0x9000 then
            return false
        end
        record = node:append { classname = "record", label = "record", id = rec_num, size = rec_len, val = resp }
        if alt then
            alt(record, resp)
        end
    end
    return true
end

function usim_map(root, amap)
    local i, v
    local sw, resp
    local child
    local file_type, ef_structure, record_length, num_records, file_size

    sw, resp = card.select("#" .. amap[2], card.SELECT_RETURN_FCP)

    if sw == 0x9000 then
        child = root:append { classname = amap[1], label = amap[3], id = amap[2] }
        if amap[1] == "file" then
            file_type, ef_structure, record_length, num_records, file_size = usim_map_descriptor(child, resp)
            if file_type == 0 or file_type == 1 then
                if ef_structure == 1 then
                    usim_read_content_binary(child, file_size, amap[4])
                elseif ef_structure == 2 or ef_structure == 6 then
                    usim_read_content_record(child, file_size, record_length, amap[4])
                end
            end
        else
            usim_map_descriptor(child, resp)
            if amap[4] then
                for i, v in ipairs(amap[4]) do
                    usim_map(child, v)
                end
            end
        end
    end
end

function pin_wrap(pin)
    local i
    local r = bytes.new(8)
    for i = 1, #pin do
        r = bytes.concat(r, string.byte(pin, i))
    end
    for i = #pin + 1, 8 do
        r = bytes.concat(r, 0xFF)
    end
    return r
end

local PIN
local sw, resp

if card.connect() then
    CARD = card.tree_startup("USIM")

    PIN = ui.readline("Enter PIN for verification (or keep empty to avoid PIN verification)", 8, "")
    if PIN == nil then
        goto exit
    end
    if PIN ~= "" then
        PIN = pin_wrap(PIN)
        sw, resp = card.send(bytes.new(8, "00 20 00 01 08", PIN)) -- unblock pin = XXXX
        if sw ~= 0x9000 then
            log.print(log.ERROR, "PIN Verification failed.")
            ui.question("PIN Verification failed, halting.", { "OK" })
            goto exit
        end
    end
    usim_map(CARD, USIM_MAP)
    if USIM_ADF_MAP[2] then
        usim_map(CARD, USIM_ADF_MAP)
    end
    :: exit ::
    card.disconnect()
    log.print(log.WARNING, "NOTE: This USIM script is still incomplete. Several data items are not analyzed.")
end


