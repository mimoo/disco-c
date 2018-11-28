"""
This script generates the string literals for the different Noise handshakes.
I could have done this by hand but it is easier to audit something that is clear.
"""

###############
# Tokens
###############

token = {
	"e":   "e",
	"s":   "s",
	"ee":  "E",
	"es":  "R",
	"se":  "D",
	"ss":  "S",
	"psk": "p",

	"end_turn": "|",
}

"""
#define token_e        'e'
#define token_s        's'
#define token_ee       'E'
#define token_es       'R'
#define token_se       'D'
#define token_ss       'S'
#define token_psk      'p'

#define token_end_turn '|'
"""


###############
# Handshake Patterns
###############

"""
N:
  <- s
  ...
  -> e, es
"""
handshake_N = {
	"name": "N",
	"pre_message_patterns": [
		[], # →
		["s"], # ←
	],
	"message_patterns": [
		["e", "es"], # →
	],
}

"""
K:
  -> s
  <- s
  ...
  -> e, es, ss
"""
handshake_K = {
	"name": "K",
	"pre_message_patterns": [
		["s"], # →
		["s"], # ←
	],
	"message_patterns": [
		["e", "es", "ss"], # →
	],
}

"""
X:
  <- s
  ...
  -> e, es, s, ss
"""
handshake_X = {
	"name": "X",
	"pre_message_patterns": [
		[],
		["s"], # ←
	],
	"message_patterns": [
		["e", "es", "s", "ss"], # →
	],
}

"""
NN:
  -> e
  <- e, ee
"""
handshake_NN = {
	"name": "NN",
	"pre_message_patterns": [
	],
	"message_patterns": [
		["e"], # →
		["e", "ee"], # ←
	],
}

"""  
KN:
	-> s
	...
	-> e
	<- e, ee, se
"""
handshake_KN = {
	"name": "KN",
	"pre_message_patterns": [
		["s"], # →
	],
	"message_patterns": [
		["e"], # →
		["e", "ee", "se"], # ←
	],
}

"""
NK:
  <- s
  ...
  -> e, es
  <- e, ee
"""
handshake_NK = {
	"name": "NK",
	"pre_message_patterns": [
		[], # →
		["s"], # ←
	],
	"message_patterns": [
		["e", "es"], # →
		["e", "ee"], # ←
	],
}


"""  
KK:
  -> s
  <- s
  ...
  -> e, es, ss
  <- e, ee, se
"""
handshake_KK = {
	"name": "KK",
	"pre_message_patterns": [
		["s"], # →
		["s"], # ←
	],
	"message_patterns": [
		["e", "es", "ss"], # →
		["e", "ee", "se"], # ←
	],
}

"""
NX:
  -> e
  <- e, ee, s, es
"""
handshake_NX = {
	"name": "NX",
	"pre_message_patterns": [
	],
	"message_patterns": [
		["e"], # →
		["e", "ee", "s", "es"], # ←
	],
}

"""  
KX:
  -> s
  ...
  -> e
  <- e, ee, se, s, es
"""
handshake_KX = {
	"name": "KX",
	"pre_message_patterns": [
		["s"], # →
	],
	"message_patterns": [
		["e"], # →
		["e", "ee", "se", "s", "es"], # ←
	],
}

"""
XN:
  -> e
  <- e, ee
  -> s, se
"""  
handshake_XN = {
	"name": "XN",
	"pre_message_patterns": [
	],
	"message_patterns": [
		["e"], # →
		["e", "ee"], # ←
		["s", "se"], # →
	],
}

"""
IN:
  -> e, s
  <- e, ee, se
"""
handshake_IN = {
	"name": "IN",
	"pre_message_patterns": [
	],
	"message_patterns": [
		["e", "s"], # →
		["e", "ee", "se"], # ←
	],
}

"""
XK:
  <- s
  ...
  -> e, es
  <- e, ee
  -> s, se
"""
handshake_XK = {
	"name": "XK",
	"pre_message_patterns": [
		[], # →
		["s"], # ←
	],
	"message_patterns": [
		["e", "es"], # →
		["e", "ee"], # ←
		["s", "se"], # →
	],
}

"""  
IK:
  <- s
  ...
  -> e, es, s, ss
  <- e, ee, se
"""
handshake_IK = {
	"name": "IK",
	"pre_message_patterns": [
		[], # →
		["s"], # ←
	],
	"message_patterns": [
		["e", "es", "s", "ss"], # →
		["e", "ee", "se"], # ←
	],
}

"""
XX:
  -> e
  <- e, ee, s, es
  -> s, se
"""
handshake_XX = {
	"name": "XX",
	"pre_message_patterns": [
	],
	"message_patterns": [
		["e"], # →
		["e", "ee", "s", "es"], # ←
		["s", "se"], # →
	],
}

"""  
IX:
  -> e, s
  <- e, ee, se, s, es
"""
handshake_IX = {
	"name": "IX",
	"pre_message_patterns": [
	],
	"message_patterns": [
		["e", "s"], # →
		["e", "ee", "se", "s", "es"], # ←
	],
}



def main():

	# I maintain a list of supported patterns, because some really sucks (NN for example)
	supported_patterns = [
		handshake_N,
		handshake_K,
		handshake_X,
		handshake_NN,
		handshake_KN,
		handshake_NK,
		handshake_KK,
		handshake_NX,
		handshake_KX,
		handshake_XN,
		handshake_IN,
		handshake_XK,
		handshake_IK,
		handshake_XX,
		handshake_IX,
	]

	# the #define C macro to generate for each handshake
	format = '#define HANDSHAKE_%s "Noise_%s_25519_STROBEv1.0.2\\0%s\\0%s\\0"'

	# disclaimer
	print("// The following defines were generated using python")
	print("// You can manually audit the handshake_patterns.py file")

	# format each pattern
	for pattern in supported_patterns:
		# get name
		name = pattern["name"]

		# get pre_message_patterns
		pre_message_patterns = ""
		for direction in pattern["pre_message_patterns"]:
			for t in direction:
				pre_message_patterns += token[t]
			pre_message_patterns += token["end_turn"]
		pre_message_patterns = pre_message_patterns[:-1] # remove last end_turn

		# get message patter
		message_patterns = ""
		for direction in pattern["message_patterns"]:
			for t in direction:
				message_patterns += token[t]
			message_patterns += token["end_turn"]
		message_patterns = message_patterns[:-1] # remove last end_turn

		# print formated #define
		print(format % (name, name, pre_message_patterns, message_patterns))



if __name__ == "__main__":
	main()
	
	
	
	
	
	
	
