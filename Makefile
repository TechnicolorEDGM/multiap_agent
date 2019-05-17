############## COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE #############
## Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          #
## All Rights Reserved                                                      #
## The source code form of this Open Source Project components              #
## is subject to the terms of the BSD-2-Clause-Patent.                      #
## You can redistribute it and/or modify it under the terms of              #
## the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) #
## See COPYING file/LICENSE file for more details.                          #
#############################################################################

#SRCDIRS :=
#LIBRARY_DIRS :=
#DOXYGEN_CONFIG := doxyfile
TARGET_NAME := multiap_agent
TARGET_LIBRARIES := -lal -lfactory -lcommon -lrt -lpcap -lcrypto -luv -lpthread -lplatform_map -lubox -lubus
#TARGET_LIBRARIES := -lal -lfactory -lcommon -lrt -lpcap -luv -lpthread -lplatform_map
TARGET_INCLUDE_DIRS :=./include

TARGET_CSRC := $(wildcard src/*.c)

ifeq ($(PLATFORM),openwrt)
EXTRA_FLAGS = -DOPENWRT
endif

TARGET_INCLUDE_FLAGS=$(foreach includedir, $(TARGET_INCLUDE_DIRS), -I$(includedir))

TARGET_OBJFILES += $(TARGET_CSRC:.c=.o)

LIBCFLAGS+=$(EXTRA_FLAGS)

CFLAGS+=$(LIBCFLAGS)
CFLAGS+= -DINT8U="unsigned char"
CFLAGS+= -DINT8U="unsigned char"
CFLAGS+= -DINT16U="unsigned short int"
CFLAGS+= -DINT32U="unsigned int"
CFLAGS+= -DINT8S="signed char"
CFLAGS+= -DINT16S="signed short int"
CFLAGS+= -DINT32S="signed int" 
CFLAGS+= -DAGENT_VERSION=\"$(AGENT_VERSION)\"

CFLAGS+= -g -Wall -Werror #-Wextra
CFLAGS+= -DMAX_NETWORK_SEGMENT_SIZE=1500

ifeq ($(ENDIANNESS), big)
CFLAGS+= -D_HOST_IS_BIG_ENDIAN_=1
else
CFLAGS+= -D_HOST_IS_LITTLE_ENDIAN_=1
endif

INCLUDE_FLAGS+=$(TARGET_INCLUDE_FLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

all: $(TARGET_OBJFILES)
	$(CC) -o $(TARGET_NAME) $(TARGET_OBJFILES) $(TARGET_LIBRARIES)

#Clean files
clean:
	rm -f $(TARGET_OBJFILES) rm -f $(TARGET_NAME)

#Make Doxygen files
#doxygen:
#	cd docs && \
#	doxygen $(DOXYGEN_CONFIG)

#Clean Doxygen files
#clean_doxygen:
#	rm -rf docs/html
#	rm -rf docs/latex
