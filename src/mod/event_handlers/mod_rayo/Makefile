BASE=../../../..

IKS_DIR=$(BASE)/libs/iksemel
IKS_LA=$(IKS_DIR)/src/libiksemel.la
LOCAL_CFLAGS += -I$(BASE)/libs/iksemel/include
LOCAL_OBJS= $(IKS_LA) \
	iks_helpers.o \
	rayo_components.o \
	rayo_input_component.o \
	rayo_output_component.o \
	rayo_prompt_component.o \
	rayo_record_component.o \
	sasl.o \
	srgs.o
LOCAL_SOURCES=	\
	iks_helpers.c \
	rayo_components.c \
	rayo_input_component.c \
	rayo_output_component.c \
	rayo_prompt_component.c \
	rayo_record_component.c \
	sasl.c \
	srgs.c
include $(BASE)/build/modmake.rules

$(IKS_LA): $(IKS_DIR) $(IKS_DIR)/.update
	@cd $(IKS_DIR) && $(MAKE)
	@$(TOUCH_TARGET)
