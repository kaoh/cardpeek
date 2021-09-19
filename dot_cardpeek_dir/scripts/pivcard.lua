-- @targets 0.8.4-win32

AID_PIV =  "#A00000030800001000"

require('lib.tlv')
require('lib.apdu')

-- Based on NIST SP 800-73-4

-- SP800-73-4 Part 2 3.1.2 GET DATA
function pivGetData(id)
        -- Tag 0x5C: Tag list
        dataField = bytes.concat(bytes.new(8,0x5c,#id, id))
        ins = 0xCB -- GET DATA
        p1 = 0x3f -- From Spec
        p2 = 0xff -- From Spec
        lc = #dataField
        le = 0
        command = bytes.concat(card.CLA,ins,p1,p2,lc,dataField,le)
        return card.send(command)
    end

    -- Based on NIST SP 800-73-4 Part 1 Table 3.5
    PIV_CONTAINER_IDS = {
        -- Mandatory Elements
        ['DB00'] = {'Card Capability Container'},
        ['3000'] = {'Card Holder Unique Identifier'},
        ['0101'] = {'X.509 Certificate for PIV Authentication'},
        ['6010'] = {'Cardholder Fingerprints'}, -- PIN Required
        ['9000'] = {'Security Object'},
        ['6030'] = {'Cardholder Facial Image'}, -- PIN Required
        ['0500'] = {'X.509 Certificate for Card Authentication'},
        -- Conditional Elements
        ['0100'] = {'X.509 Certificate for Digital Signature'},
        ['0102'] = {'X.509 Certificate for Key Management'},
        -- Optional Elements
        ['3001'] = {'Printed Information'},
-- More
        ['1018'] = {'Pairing Code Reference Data Container'}
    }

    function ui_parse_YYYYMMDD(node,data)
        if #data == 8 then
        local d = tostring(data)
        local d_table = {
          ['year']=0+string.sub(d,1,4),
          ['month']=0+string.sub(d,5,6),
          ['day']=0+string.sub(d,7,8)}
        local t
    
        t = os.time(d_table)
    
        nodes.set_attribute(node,"val",data)
        nodes.set_attribute(node,"alt",os.date("%x",t))
        return true
        end
        return false
    end

    local ui_parse_certinfo_tbl =
    {
      [0] = "Uncompressed",
      [1] = "GZIP Compressed",
    }

    function ui_parse_certinfo(node,data)
        nodes.set_attribute(node,"val",data)
        nodes.set_attribute(node,"alt",ui_parse_certinfo_tbl[data:get(0)])
    end

    function ui_parse_guid(node,data)
        -- FIXME: Byte order isn't validated yet.
        node:set_attribute("val",data)
        local d1 = data:sub(0,3):tonumber()
        local d2 = data:sub(4,5):tonumber()
        local d3 = data:sub(6,7):tonumber()
        local d4 = data:sub(8,9):tonumber()
        local d5 = data:sub(10,11):tonumber()
        local d6 = data:sub(12,13):tonumber()
        local d7 = data:sub(14,15):tonumber()
        -- 8-4-4-4-12
        node:set_attribute("alt",string.format("%8x-%4x-%4x-%4x-%4x%4x%4x", d1, d2, d3, d4, d5, d6, d7))
    end

    -- Tags in PIV Containers
    PIV_CONTAINER_TLV = {
        ['01'] = {"Name", ui_parse_printable},
        ['02'] = {"Employee Affiliation", ui_parse_printable},
        ['04'] = {"Expiration date", ui_parse_YYYYMMDD},
        ['05'] = {"Agency Card Serial Number", ui_parse_printable},
        ['06'] = {"Issuer Identification", ui_parse_printable},
        ['07'] = {"Organization Affiliation (Line 1)", ui_parse_printable},
        ['08'] = {"Organization Affiliation (Line 2)", ui_parse_printable},
        ['30'] = {"FASC-N", ui_parse_printable},
        ['32'] = {"Organizational Identifier"},
        ['33'] = {"DUNS",ui_parse_printable}, -- 9-Digit, Fixed
        ['34'] = {"GUID",ui_parse_guid},
        ['35'] = {"Expiration Date", ui_parse_YYYYMMDD},
        ['36'] = {"Cardholder UUID", ui_parse_guid},
        ['3E'] = {"Issuer Asymmetric Signature"},
        ['70'] = {"Certificate"},
        ['71'] = {"CertInfo", ui_parse_certinfo},
        ['72'] = {"MSCUID"}, -- Obsolete
        ['7F21'] = {"Intermediate CVC"},
        ['99'] = {"Pairing Code", ui_parse_printable},
        ['B4'] = {"Security Object Buffer"}, -- Obsolete
        ['BA'] = {"Mapping of DG to ContainerID"},
        ['BB'] = {"Security Object"},
        ['BC'] = {"Image"}, -- Fingerprint, Facial Image, Iris, etc.
        ['C1'] = {"keysWithOnCardCerts"},
        ['C2'] = {"keysWithOffCardCerts"},
        ['E3'] = {"Extended Application CardURL"},
        ['EE'] = {"Buffer Length"},
        ['F0'] = {"Card Identifier"},
        ['F1'] = {"Capability Container version number"},
        ['F2'] = {"Capability Grammar version number"},
        ['F3'] = {"Applications CardURL"},
        ['F4'] = {"PKCS#15"},
        ['F5'] = {"Registered Data Model number"},
        ['F6'] = {"Access Control Rule Table"},
        ['F7'] = {"Card APDUs"},
        ['FA'] = {"Redirection Tag"},
        ['FB'] = {"Capability Tuples (CTs)"},
        ['FC'] = {"Status Tuples (STs)"},
        ['FD'] = {"Next CCC"},
        ['FE'] = {"Error Detection Code"}
    }

    -- Override due to PIV implementation issues.
function tlv_tag_is_compound_orig(tag)
    return (bit.AND(tlv_tag_msb(tag),0x20)==0x20)
end

function tlv_tag_is_compound_piv(tag)
    return false
end

tlv_tag_is_compound = tlv_tag_is_compound_orig

    function ui_parse_PIV(node,data)
        tlv_tag_is_compound = tlv_tag_is_compound_piv
        if #data==0 then
            return false
        end
        tlv_parse(node, data, PIV_CONTAINER_TLV)
        tlv_tag_is_compound = tlv_tag_is_compound_orig
    end

    PIV_TLV = {
        ['53'] = {"PIV Container", ui_parse_PIV },
        ['7E'] = {"Discovery Object" },
        ['7F61'] = {"BIT Group Template" }
    }

-- From Table 6-2, SP800-78
PIV_CAI =
{
    [0x00] = {"3 Key Triple DES – ECB"},
    [0x03] = {"3 Key Triple DES – ECB"},
    [0x06] = {"RSA 1024 bit modulus, 65 537 ≤ exponent ≤ 2256 - 1"},
    [0x07] = {"RSA 2048 bit modulus, 65 537 ≤ exponent ≤ 2256 - 1"},
    [0x08] = {"AES-128 – ECB"},
    [0x0A] = {"AES-192 – ECB"},
    [0x0C] = {"AES-256 – ECB"},
    [0x11] = {"ECC: Curve P-256"},
    [0x14] = {"ECC: Curve P-384"},
    [0x27] = {"Cipher Suite 2"},
    [0x2E] = {"Cipher Suite 7"}
}


function parse_piv_cai(node, data)
    nodes.set_attribute(node,"val",data)
    nodes.set_attribute(node,"alt",PIV_CAI[data:get(0)])
end

-- For SELECT response
PIV_APT_REFERENCE = {
    ['61'] = {"Application Property Template"},
    ['79'] = {"Coexistent tag allocation authority"},
    ['AC'] = {"Cryptographic algorithms supported"},
    ['AC/80'] = {"Cryptographic algorithm identifier", parse_piv_cai } -- Refer to PIV_CAI
}

function piv_parse_tag(parent, id, label)
    local node
    sw, resp=pivGetData(bytes.new(8,id))
    if sw == 0x9000 and #resp > 0 then
        node=tlv_parse(parent, resp, PIV_TLV)
        node:set_attribute("label",label)
        node:set_attribute("id",nil)
    end

end

if card.connect(AID_PIV, 0) then
    local CARD
    CARD = card.tree_startup("PIV")
    sw, resp = card.select(AID_PIV)
    if sw == 0x9000 then

        tlv_parse(CARD, resp, PIV_APT_REFERENCE)
        -- Mandatory
        piv_parse_tag(CARD, "5FC107", "Card Capability Container");
        piv_parse_tag(CARD, "5FC102", "CHUID");
        piv_parse_tag(CARD, "5FC105", "X.509 Certificate for PIV Authentication");
        piv_parse_tag(CARD, "5FC103", "Cardholder Fingerprints");
        piv_parse_tag(CARD, "5FC106", "Security Object");
        piv_parse_tag(CARD, "5FC108", "Cardholder Facial Image");
        piv_parse_tag(CARD, "5FC101", "X.509 Certificate for Card Authentication");
        -- Conditional
        -- Optional
    end

card.disconnect()
end
