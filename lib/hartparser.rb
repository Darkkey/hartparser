def bin_to_hex(s)
  s.each_byte.map { |b| b.to_s(16) + " " }.join
end

# Hart commands
HART_CMD_0_READ_UID = 0
HART_CMD_1_READ_PV = 1
HART_CMD_2_READ_LC = 2 # !
HART_CMD_3_READ_DV_LC = 3
HART_CMD_6_WRITE_POLLID = 6
HART_CMD_8_READ_DYNVAR_CLASS = 8
HART_CMD_12_READ_MSG =  12
HART_CMD_13_READ_TAG =  13
HART_CMD_14_READ_PVTRANSDUCER_INFO = 14
HART_CMD_15_READ_DEVICE_INFO = 15
HART_CMD_16_READ_FINAL_ASSEMBLY_NUMBER = 16
HART_CMD_20_READ_LONGTAG = 20
HART_CMD_22_WRITE_LONGTAG = 22
HART_CMD_48_READ_ADDITIONAL = 48 # !
# /Hart commands

def from_packed_ascii(pstr)
	i = 0
	retstr = ""
	
	while i < pstr.length 
		parr = [pstr[i] & 0x3F, pstr[i + 1]>>6 | ((pstr[i + 1] << 2 ) & 0x3F),
				pstr[i + 1]>>4 | ((pstr[i + 2] << 4 ) & 0x3F),
				pstr[i + 2]>>2]
		parr.collect! { |a| a | (~(a << 1) & 0x40) } 		
		parr.collect! { |a| a & 0x7F }
		
		retstr += parr.pack("c*")
		
		i += 3
	end
	
	return retstr
end

def to_packed_ascii(str)
	i = 0
	retpstr = ""
	
	while i < str.length
		ret = [0,0,0]
		ret[0] = (str[i].ord << 2) & 252
		ret[0] = ret[0] | (((str[i+1].ord << 2) & 192) >> 6 )

		ret[1] = (str[i+1].ord << 4) & 240
		ret[1] = ret[1] | (((str[i+2].ord << 2) & 240) >> 4)
		
		ret[2] = ((str[i+2].ord << 6) & 192) | (str[i+3].ord & 0x3F)

		retpstr += ret.pack("c*")
		
		i += 4
	end
	
	return retpstr
end

class Hartaddr
	HART_PRIMARY_MASTER = 1
	HART_SECONDARY_MASTER = 0

	attr_accessor :unique
	attr_accessor :master_type
	attr_accessor :burst
	attr_accessor :manufacturer_id
	attr_accessor :polling_id
	attr_accessor :device_type
	attr_accessor :deviceUID
	attr_accessor :preamble
	
	attr_accessor :incorrectpreamble
	
	def initialize(addr = nil)
		@unique = false
		@incorrectpreamble = false
		
		parse(addr) if addr
		
	end
	
	def parse(addr)
		@preamble = addr[0].to_i()
		@master_type = @preamble[7]
		@burst = @preamble[6]
			
		if addr.length > 1 then
			@unique = true 
			
			@manufacturer_id = @preamble & 0x3F
			@device_type = addr[1].to_i()
			@deviceUID = addr[2..-1]
		else
			@unique = false
			
			@polling_id = @preamble & 0x3F
		end
	end
	
end

class Hartpdu
	HART_FSK = 0
	HART_C8PSK = 1
	HART_POLLING = 0
	HART_UNIQ = 1
	HART_BACK_FRAME = 1
	HART_STX_FRAME = 2
	HART_ACK_FRAME = 6

	attr_accessor :preamble
	attr_accessor :delimeter
	attr_accessor :address
	attr_accessor :expbytes
	attr_accessor :command
	attr_accessor :bytecount
	attr_accessor :data
	attr_accessor :checkbyte
	
	attr_accessor :response
	attr_accessor :status
	
	attr_accessor :correctlen
	attr_accessor :correctcrc

	def initialize(packet = nil)

		@correctlen = true
		@correctcrc = true
		
		parse(packet) if packet
	end

	def parse(packet)
		packarr = packet.unpack('C*')

		idx = 0
		
		@preamble = packarr.index { |x| x != 255 }

		idx += @preamble

		@delimeter = packarr[@preamble].to_i
		addr_type = get_addrtype()
		expbyteslen = get_expbyteslen()
		lowlayer_type = get_physlayer_type()
		frame_type = get_frame_type()

		idx += 1
		
		if addr_type == 0
			@address = Array(packarr[idx])
		else
			@address = packarr[idx, 5]	
		end

		idx += @address.length

		if expbyteslen > 0
			@expbytes = packarr[idx, expbyteslen]
		end

		idx += expbyteslen

		@command = packarr[idx].to_i()

		idx += 1

		@bytecount = packarr[idx].to_i()

		idx += 1

		if frame_type == HART_ACK_FRAME then
			@response = packarr[idx].to_i()
			idx += 1
			@status = packarr[idx].to_i()
			idx += 1
			@bytecount -= 2
		end
		
		@data = packarr[idx, @bytecount]

		idx += @bytecount

		@checkbyte = packarr[idx]
	end

	def get_crc(string)
		return string.bytes.inject {|crc,b| crc ^ b }
	end
	
	def to_str()
		frame_type = get_frame_type()
		
		lenadd = if frame_type == HART_ACK_FRAME then 2 else 0 end
		
		result = "\xFF" * preamble
		result += @delimeter.chr
		
		result += @address.pack('c*')
		
		puts @expbytes
		result += @expbytes.pack('c*') if @expbytes != nil
		
		result += @command.chr
		
		result += if correctlen then (@data.length + lenadd).chr else @bytecount.chr end
		
		if frame_type == HART_ACK_FRAME then
			result += @response.chr
			result += @status.chr
			
		end
		
		result += @data.to_s() if @data.length > 0
		
		@checkbyte = get_crc(result[preamble..-1]) if @correctcrc 
		
		result += @checkbyte.chr
		
		return result
	end
	
	def set_addrtype(type)
		@delimeter = @delimeter & 0xFE | (type<<7 & 0x80)
	end
	
	def get_addrtype()
		return @delimeter[7]
	end
	
	def get_expbyteslen()
		return @delimeter[6] * 2 + @delimeter[5] * 1
	end
	
	def get_physlayer_type()
		return @delimeter[4] * 2 + @delimeter[3] * 1
	end
	
	def get_frame_type()
		return @delimeter[2]*4 + @delimeter[1] * 2 + @delimeter[0] * 1
	end
end

class Hartrequestparser
	attr_accessor :debug
	
	attr_accessor :parsecmd
	attr_accessor :createcmd
	
	def initialize
		debug = false
		
		@parsecmd = {
			HART_CMD_0_READ_UID => :command0rq_parse,
			HART_CMD_1_READ_PV => :command1rq_parse,
			HART_CMD_2_READ_LC => :command2rq_parse,
			HART_CMD_3_READ_DV_LC => :command3rq_parse,
			HART_CMD_6_WRITE_POLLID => :command6rq_create,
			HART_CMD_8_READ_DYNVAR_CLASS => :command8rq_parse,
			HART_CMD_12_READ_MSG => :command12rq_parse,
			HART_CMD_13_READ_TAG => :command13rq_parse,
			HART_CMD_14_READ_PVTRANSDUCER_INFO => :command14rq_parse,
			HART_CMD_15_READ_DEVICE_INFO => :command15rq_parse,
			HART_CMD_16_READ_FINAL_ASSEMBLY_NUMBER => :command16rq_parse,
			HART_CMD_20_READ_LONGTAG => :command20rq_parse,
			HART_CMD_22_WRITE_LONGTAG => :command22rq_parse,			
			HART_CMD_48_READ_ADDITIONAL => :command48rq_parse
		}
		
		@createcmd = {
			HART_CMD_0_READ_UID => :command0rq_create,
			HART_CMD_6_WRITE_POLLID => :command6rq_parse,
			HART_CMD_22_WRITE_LONGTAG => :command22rq_create
		}
		# do nothing
	end
	
	def parse(commandid, data)
		return send(@parsecmd[commandid], data)
	end
	
	def create(commandid, args)
		return send(@createcmd[commandid], args)
	end
	
	def command0rq_parse(data)
		puts "Command 0 request with no args." if @debug
		return [0]
	end
	
	def command1rq_parse(data)
		puts "Command 1 request with no args." if @debug
		return [0]
	end
	
	def command2rq_parse(data)
		puts "Command 2 request with no args." if @debug
		return [0]
	end
	
	def command3rq_parse(data)
		puts "Command 3 request with no args." if @debug
		return [0]
	end
	
	def command6rq_parse(data)
        ret = {"polling_id" => data[0].ord, "lc_mode" => data[0].ord}
        puts "Command 6 request " + ret.inspect if @debug
        return ret
    end

    def command6rq_create(args)
    	ret = args["polling_id"].chr + args["lc_mode"].chr
        puts "Command 6 create " + bin_to_hex(ret) if @debug
        return ret
    end
	
	def command8rq_parse(data)
		puts "Command 8 request with no args." if @debug
		return [0]
	end
	
	def command12rq_parse(data)
		puts "Command 12 request with no args." if @debug
		return [0]
	end
	
	def command13rq_parse(data)
		puts "Command 13 request with no args." if @debug
		return [0]
	end
	
	def command14rq_parse(data)
		puts "Command 14 request with no args." if @debug
		return [0]
	end
	
	def command15rq_parse(data)
		puts "Command 15 request with no args." if @debug
		return [0]
	end
	
	def command16rq_parse(data)
		puts "Command 15 request with no args." if @debug
		return [0]
	end
	
	def command20rq_parse(data)
		puts "Command 20 request with no args." if @debug
		return [0]
	end

        def command22rq_parse(data)
                ret = {"longtag" => data.pack("c*")
                }
                puts "Command 22 request " + ret.inspect if @debug
                return ret
        end

        def command22rq_create(args)
       		ret = args["longtag"]
                puts "Command 22 create " + bin_to_hex(ret) if @debug
                return ret
        end

	
	def command48rq_parse(data)
		puts "Command 48 request with no args." if @debug
		return [0]
	end
	
	def command0rq_create(args)
		return nil
	end
end

class Hartresponseparser
	attr_accessor :debug

	attr_accessor :parsecmd
	attr_accessor :createcmd
	
	def initialize
		debug = false
		
		@parsecmd = {
			HART_CMD_0_READ_UID => :command0rs_parse,
			HART_CMD_1_READ_PV => :command1rs_parse,
			HART_CMD_2_READ_LC => :command2rs_parse,
			HART_CMD_3_READ_DV_LC => :command3rs_parse,
			HART_CMD_6_WRITE_POLLID => :command6rs_parse,
			HART_CMD_8_READ_DYNVAR_CLASS => :command8rs_parse,
			HART_CMD_12_READ_MSG => :command12rs_parse,
			HART_CMD_13_READ_TAG => :command13rs_parse,
			HART_CMD_14_READ_PVTRANSDUCER_INFO => :command14rs_parse,
			HART_CMD_15_READ_DEVICE_INFO => :command15rs_parse,
			HART_CMD_16_READ_FINAL_ASSEMBLY_NUMBER => :command16rs_parse,
			HART_CMD_20_READ_LONGTAG => :command20rs_parse,
			HART_CMD_22_WRITE_LONGTAG => :command22rs_parse,
			HART_CMD_48_READ_ADDITIONAL => :command48rs_parse
		}
		
		@createcmd = {
			HART_CMD_0_READ_UID => :command0rs_create,
			HART_CMD_1_READ_PV => :command1rs_create,
			HART_CMD_2_READ_LC => :command2rs_create,
			HART_CMD_3_READ_DV_LC => :command3rs_create,
			HART_CMD_6_WRITE_POLLID => :command6rs_create,
			HART_CMD_12_READ_MSG => :command12rs_create,
			HART_CMD_13_READ_TAG => :command13rs_create,
			HART_CMD_14_READ_PVTRANSDUCER_INFO => :command14rs_create,
			HART_CMD_15_READ_DEVICE_INFO => :command15rs_create,
			HART_CMD_16_READ_FINAL_ASSEMBLY_NUMBER => :command16rs_create,
			HART_CMD_20_READ_LONGTAG => :command20rs_create,
			HART_CMD_22_WRITE_LONGTAG => :command22rs_create,
			HART_CMD_48_READ_ADDITIONAL => :command48rs_create
		}
		# do nothing
	end
	
	def parse(commandid, data)
		return send(@parsecmd[commandid], data)
	end
	
	def create(commandid, args)
		return send(@createcmd[commandid], args)
	end
	
	def command0rs_parse(data)
		ret = {"manufacturer_id" => data[1].ord, "device_type" => data[2].ord,
			"min_preambles_rq" => data[3].ord, "HART_revision" => data[4].ord,
			"device_revision" => data[5].ord, "firmware_revision" => data[6].ord,
			"hardware_revision_level" => data[7].ord & 0xF8, "signalling_code" => data[7].ord & 0x07,
			"flags" => data[8].ord, "device_id" => data[9..11].pack("c*") }
		if data.length > 12
			ret["min_preambles_rs"] = data[12].ord
			ret["max_variables"] = data[13].ord
			ret["config_change_cnt"] = data[14]*256 + data[15]
			ret["ext_status"] = data[16].ord
		end
		puts "Command 0 response " + ret.inspect if @debug
		return ret
	end
	
	def command0rs_create(args)
		ret = "\xfe" + args["manufacturer_id"].chr + args["device_type"].chr +
			args["min_preambles_rq"].chr + args["HART_revision"].chr + 
			args["device_revision"].chr + args["firmware_revision"].chr +
			(args["hardware_revision_level"] | args["signalling_code"]).chr +
			args["flags"].chr + args["device_id"] + args["min_preambles_rs"].chr +
			args["max_variables"].chr + [args["config_change_cnt"]].pack("S<") + args["ext_status"].chr
	
		puts "Command 0 response " + bin_to_hex(ret) if @debug
		return ret
	end 
	
	def command1rs_parse(data)
		ret = {"PV_units" => data[0].ord,
			"PV" => data[1..4].pack("c*").unpack("g")}
	
		puts "Command 1 response " + ret.inspect if @debug
		return ret
	end
	
	def command1rs_create(args)
		ret = [args["PV_LC"]].pack("g") + 
			[args["PV_PR"]].pack("g")
	
		puts "Command 1 response " + bin_to_hex(ret) if @debug
		return ret
	end
	
	def command2rs_parse(data)
		ret = {"PV_LC" => data[0..3].pack("c*").unpack("g"),
			"PV_PR" => data[4..7].pack("c*").unpack("g")}
	
		puts "Command 2 response " + ret.inspect if @debug
		return ret
	end
	
	def command2rs_create(args)
		ret = args["PV_units"].chr + 
			[args["PV"]].pack("g")
	
		puts "Command 2 response " + bin_to_hex(ret) if @debug
		return ret
	end
	
	def command3rs_parse(data)
		ret = {"PV_LC" => data[0..3].pack("c*").unpack("g"),
			"PV_units" => data[4].ord,
			"PV" => data[5..8].pack("c*").unpack("g"),
			"SV_units" => data[9].ord,
			"SV" => data[10..3].pack("c*").unpack("g"),
			"TV_units" => data[14].ord,
			"TV" => data[15..18].pack("c*").unpack("g"),
			"QV_units" => data[19].ord,
			"QV" => data[20..23].pack("c*").unpack("g")
		}
		puts "Command 3 response " + ret.inspect if @debug
		return ret
	end
	
	def command3rs_create(args)
		ret = [args["PV_LC"]].pack("g") +
			args["PV_units"].chr +
			[args["PV"]].pack("g") +
			args["SV_units"].chr +
			[args["SV"]].pack("g") +
			args["TV_units"].chr +
			[args["TV"]].pack("g") +
			args["QV_units"].chr +
			[args["QV"]].pack("g")
		
		puts "Command 3 response " + ret.inspect if @debug
		return ret
	end
	
	def command6rs_parse(data)
        ret = {"polling_id" => data[0].ord, "lc_mode" => data[0].ord}
        puts "Command 6 request " + ret.inspect if @debug
        return ret
    end

    def command6rs_create(args)
    	ret = args["polling_id"].chr + args["lc_mode"].chr
        puts "Command 6 create " + bin_to_hex(ret) if @debug
        return ret
    end

	def command8rs_parse(data)
	
		ret = {"PV_class" => data[0].ord, "SV_class" => data[1].ord,
			"TV_class" => data[2].ord, "QV_class" => data[3].ord
		}
		puts "Command 8 response " + ret.inspect if @debug
		return ret
	end
	
	def command12rs_parse(data)
	
		ret = {"msg" => from_packed_ascii(data)
		}
		puts "Command 12 response " + ret.inspect if @debug
		return ret
	end
	
	def command12rs_create(args)
	
		ret = to_packed_ascii(args["msg"])
		puts "Command 12 response " + bin_to_hex(ret) if @debug
		return ret
	end
	
	def command13rs_parse(data)
		ret = {"tag" => from_packed_ascii(data[0..5]),
			"descriptor" => from_packed_ascii(data[6..17]),
			"date" => data[18].ord.to_s() + "/" + data[19].ord.to_s() + "/" + (data[20].ord + 1900).to_s()
		}
		puts "Command 13 response " + ret.inspect if @debug
		return ret
	end
	
	def command13rs_create(args)
		datearr = args["date"].split("/")
	
		ret = to_packed_ascii((args["tag"] + "\x00"*(args["tag"].length - 6).abs)[0..7])  + 
			to_packed_ascii((args["descriptor"] + "\x00"*(args["descriptor"].length - 6).abs)[0..15])  + 
			datearr[0].to_i().chr + datearr[1].to_i().chr + (datearr[2].to_i() - 1900).chr 
	
		puts "Command 13 response " + bin_to_hex(ret) if @debug
		return ret
	end
	
	def command14rs_parse(data)
		ret = {"transducer_serial" => data[0].ord * 65536 + data[1].ord * 256 + data[2].ord,
			"transducer_UC" => data[3].ord,
			"upper_transducer_limit" => data[4..7].pack("c*").unpack("g"),
			"lower_transducer_limit" => data[8..11].pack("c*").unpack("g"),
			"minimum_span" => data[12..15].pack("c*").unpack("g")
		}
		puts "Command 14 response " + ret.inspect if @debug
		return ret
	end
	
	def command14rs_create(args)
		ret = args["transducer_serial"].div(65536).chr + 
			args["transducer_serial"].modulo(65536).div(256).chr +
			args["transducer_serial"].modulo(65536).modulo(256).chr +
			args["transducer_UC"].chr + 
			[args["upper_transducer_limit"]].pack("g") +
			[args["lower_transducer_limit"]].pack("g") +
			[args["minimum_span"]].pack("g")
		
		puts "Command 14 response " + ret if @debug
		return ret
	end
	
	def command15rs_parse(data)
	
		ret = {"PV_alarm_selcode" => data[0].ord, "PV_transfer_funccode" => data[1].ord,
			"PV_ranges_unitcode" => data[2].ord, "PV_upper_range_value" => data[3..6].pack("c*").unpack("g"),
			"PV_lower_range_value" => data[7..10].pack("c*").unpack("g"), "PV_damping_value" => data[3..6].pack("c*").unpack("g"),
			"write_protect_code" => data[15].ord, "private_label_distributor_code" => data[16].ord }
		
		if data.length > 17
			ret["PV_analog_channel_flags"] = data[17].ord
		end
		
		puts "Command 15 response " + ret.inspect if @debug
		return ret
	end
	
	def command15rs_create(args)
	
		ret =  args["PV_alarm_selcode"].chr + args["PV_transfer_funccode"].chr +
			args["PV_ranges_unitcode"].chr + 
			[args["PV_upper_range_value"]].pack("g") +
			[args["PV_lower_range_value"]].pack("g") + 
			[args["PV_damping_value"]].pack("g") +
			args["write_protect_code"].chr + args["private_label_distributor_code"].chr + args["PV_analog_channel_flags"].chr 

		puts "Command 15 response " + ret.inspect if @debug
		return ret
	end
	
	def command16rs_parse(data)
		ret = {"final_assembly_number" => data[0].ord * 65536 + data[1].ord * 256 + data[2].ord
		}
		puts "Command 16 response " + ret.inspect if @debug
		return ret
	end
	
	def command16rs_create(args)
		ret = args["final_assembly_number"].div(65536).chr + 
			args["final_assembly_number"].modulo(65536).div(256).chr +
			args["final_assembly_number"].modulo(65536).modulo(256).chr
		
		puts "Command 16 response " + ret if @debug
		return ret
	end
	
	def command20rs_parse(data)
	
		ret = {"longtag" => data.pack("c*")
		}
		puts "Command 20 response " + ret.inspect if @debug
		return ret
	end
	
	def command20rs_create(args)
		ret = args["longtag"]
		puts "Command 20 response " + bin_to_hex(ret) if @debug
		return ret
	end

    def command22rs_parse(data)
        puts "Command 22 response with no args." if @debug
        return [0]
    end

    def command22rs_parse(data)
        puts "Command 22 response with no args." if @debug
        return [0]
    end
	
	def command48rs_parse(data)
		ret = {"params" => data.pack("c*")
		}
		puts "Command 48 response " + ret.inspect if @debug
		return ret
	end
	
	def command48rs_create(args)
		ret = args["params"]
		puts "Command 48 response " + bin_to_hex(ret) if @debug
		return ret
	end
	
end

