
* Copyright 2019 Comcast Cable Communications Management, LLC 
* Licensed under the Apache License, Version 2.0 (the "License"); 
* you may not use this file except in compliance with the License. 
* You may obtain a copy of the License at 
* http://www.apache.org/licenses/LICENSE-2.0 
* Unless required by applicable law or agreed to in writing, software 
* distributed under the License is distributed on an "AS IS" BASIS, 
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
*  See the License for the specific language governing permissions and 
*  limitations under the License. * * SPDX-License-Identifier: Apache-2.0
* 
 
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <cbor.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <float.h>
#include <errno.h>

#define DATE_MAX_SIZE 32
#define BUFFER_SIZE 2000
#define CBOR_BLOCK_COUNT_ITEMS 12
#define SIGNATURE_LENGTH 73
#define RANDOM_MAX_LENGTH 256
#define COMMAND_MAX_LENGTH 16
#define COMMAND_MAX_COUNT 10
#define OUTPUT_NODE_MAX_LENGTH 40
#define TIME_ARRAYS_COUNT 10
#define TIME_ARRAYS_VERIFICATION_OFFSET 6
#define PUBLIC_KEY_FILE_NAME "prime256v1.pub"
#define PRIVATE_KEY_FILE_NAME "prime256v1.key"
#define CHECK_NULL_AND_FREE(ptr) \
    do                                   \
        if (NULL != (ptr))               \
        {                                \
            free((ptr));  \
            (ptr) = NULL;                \
        }                                \
    while (0)

#define CALL_CBOR_CHECK_FUNCTION(func_call, expected, ret_val)\
    do{\
        /*CborError err = CborNoError;*/\
        if(expected != (func_call)) \
        {\
            return ret_val;\
        }\
    }\
    while(0)

#define CALL_CBOR_PARSE_FUNCTION(func_call)\
    do{\
        CborError err = CborNoError;\
        if(CborNoError != (err = (func_call))) \
        {\
            return err;\
        }\
    }\
    while(0)

#ifdef ENABLE_DEBUG_MSG
#define CALL_CBOR_ENCODE_FUNCTION(func_call, container)\
    do{\
        CborError err = CborNoError;\
        if(CborNoError != (err = (func_call))) \
        {\
            print_debug_info(err, &container);\
            return err;\
        }\
    }\
    while(0)
#else
#define CALL_CBOR_ENCODE_FUNCTION(func_call, container)\
    CALL_CBOR_PARSE_FUNCTION(func_call)
#endif
#ifdef ENABLE_DEBUG_MSG
#define CALL_DEBUG_MSG(func_call)\
        do{\
            func_call;\
        }\
        while(0)
#else
#define CALL_DEBUG_MSG(func_call)
#endif

#ifndef COMMON_DEBUG
#define COMMON_DEBUG 0
#endif

#ifdef __arm__
#define FORMAT "%"
#else
#define FORMAT "%l"
#endif

#ifdef __arm__
#define FORMAT_UINT64 "%ll"
#else
#define FORMAT_UINT64 "%l"
#endif

typedef struct {
    int count_files;
    char* file_to_validate;
    char* file_with_key;
    bool verify_after_sign;
    uint64_t inputNode;
    bool inputNode_valid;
    uint64_t outputNode;
    bool outputNode_valid;
    uint64_t targetNode;
    bool targetNode_valid;
} T_configuration;

typedef struct {
    uint8_t signature[SIGNATURE_LENGTH];
    uint8_t type;
    uint64_t input_node;
    uint64_t output_node;
    uint64_t target_node;
    uint64_t not_before;
    uint8_t action;
    uint16_t command[COMMAND_MAX_COUNT];
    size_t command_count;
    uint64_t block_heigth;
    uint64_t create_date;
    uint64_t exp;
    uint64_t txn_time;

} T_cbor_typical_block;

typedef struct {
    EC_KEY* eckey;
    EVP_PKEY* pkey;
} T_keys;

typedef struct {
    double min;
    double max;
    double avg;
    double median;
} T_times;

typedef struct {
    uint8_t *start;
    size_t length;
} T_array_chunk;

#define SIGNATURE_INDEX 0
#define TXN_TIME_INDEX 10
#define TYPE_INDEX 11
static const char *names[]=
{
    "sig",
    "iN",
    "oN",
    "tN",
    "notBefore",
    "action",
    "cmd",
    "block",
    "cDate",
    "exp",
    "txnTime",
    "type"
};

typedef enum
{
    CSB_OK = 1,
    CSB_NO_ECKEY,
    CSB_NO_EVP_PKEY,
    CSB_UNSUPPORTED_FEATURE,
    CSB_KEY_FILE_ERROR,
    CSB_NULL_START_BUFFER,
    CSB_NULL_END_BUFFER,
    CSB_RANDOM_STRING_FAILED,
    CSB_FAILED_TO_CREATE_KEY_FILE,
    CSB_FAILED_TO_SAVE_KEY,
    CSB_SIGNATURE_SIZE_MISMATCH,
    CSB_MALLOC_FAILED,
    CSB_FILE_TOO_BIG,
    CSB_FILE_OPEN_FAILED,
    CSB_VALUE_AT_END,
    CSB_VALUE_NOT_MAP,
    CSB_VALUE_NOT_INT,
    CSB_VALUE_NOT_STRING,
    CSB_INCORRECT_SIGNATURE,
    CSB_SIGNATURE_LENGTH_INCREASED,
    CBOR_SIZE_INDEFINITE,
    CBOR_TINY_UNKNOWN_ERROR,
} T_return_codes;

time_t g_time_placeholder = 0;
extern int errno ;

void print_array(int do_printf, FILE *stream, const uint8_t *array, const size_t len)
{
    size_t i = 0;
    if (stream == NULL)
        stream = stdout;
    if (do_printf)
    {
        fprintf(stream, "Length: "FORMAT"d\n", len);
        for (i = 0; i < len; ++i)
            fprintf(stream, "%02hhX", array[i]);
        fprintf(stream, "\n");
    }
}

void print_double_array(int do_printf, FILE *stream, const double *array, const size_t len)
{
    size_t i = 0;
    if (stream == NULL)
        stream = stdout;
    if (do_printf)
    {
        fprintf(stream, "Length: "FORMAT"d\n", len);
        for (i = 0; i < len; ++i)
            fprintf(stream, "%f, ", array[i]);
        fprintf(stream, "\n");
    }
}


void print_usage(char *own_name)
{
    printf("%s usage:\n", own_name);
    printf("  %s <options>\n", own_name);
    printf("\t-N <count files> - count of CBOR files to be created\n");
    printf("\t-f <CBOR file>   - name of CBOR file to be validated\n");
    printf("\t-k <key file>    - name of file with key\n");
    printf("\t-i <input node>  - input node ID\n");
    printf("\t-o <output node> - output node ID\n");
    printf("\t-t <target node> - target node ID\n");
    printf("\t-v               - validate all files right after signing N (default 50) CBOR files and do not validate them\n");
    exit(1);
}

#define SWAP_ELEMENTS(a,b) { register double t=(a);(a)=(b);(b)=t; }
double get_median(double arr[], unsigned int n)
{
    unsigned int  low = 0 ;
    unsigned int  high = n-1;
    unsigned int  median = (low + high) / 2;
    unsigned int  middle;
    unsigned int  ll;
    unsigned int  hh;
    for (;;) {
        if (high <= low) /* One element only */
            return arr[median] ;
        if (high == low + 1) { /* Two elements only */
            if (arr[low] > arr[high])
                SWAP_ELEMENTS(arr[low], arr[high]) ;
            return arr[median] ;
        }
    /* Find median of low, middle and high items; swap into position low */
        middle = (low + high) / 2;
        if (arr[middle] > arr[high])
            SWAP_ELEMENTS(arr[middle], arr[high]) ;
        if (arr[low] > arr[high])
            SWAP_ELEMENTS(arr[low], arr[high]) ;
        if (arr[middle] > arr[low])
            SWAP_ELEMENTS(arr[middle], arr[low]) ;
        /* Swap low item (now in position middle) into position (low+1) */
        SWAP_ELEMENTS(arr[middle], arr[low+1]) ;
        /* Nibble from each end towards middle, swapping items when stuck */
        ll = low + 1;
        hh = high;
        for (;;) {
            do ll++; while (arr[low] > arr[ll]) ;
            do hh--; while (arr[hh] > arr[low]) ;
            if (hh < ll)
            break;
            SWAP_ELEMENTS(arr[ll], arr[hh]) ;
        }
        /* Swap middle item (in position low) back into correct position */
        SWAP_ELEMENTS(arr[low], arr[hh]) ;
        /* Re-set active partition */
        if (hh <= median)
            low = ll;
        if (hh >= median)
            high = hh - 1;
    }
    return arr[median] ;
}

inline
size_t get_cbor_buffer_length(uint8_t *encoder_data_ptr, uint8_t *buffer)
{
    return encoder_data_ptr - buffer;
}

inline
size_t get_random_in_range(size_t max_random)
{
    return rand() % max_random + 1;
}

void parse_command_line(T_configuration* config, int argc, char *argv[])
{
    int option = 0;
    assert(NULL != config);
    config->count_files = 50;
    config->file_to_validate = NULL;
    config->file_with_key = NULL;
    config->inputNode_valid = false;
    config->outputNode_valid = false;
    config->targetNode_valid = false;

    while ((option = getopt(argc, argv, "N:f:k:i:o:t:v::h?")) != -1)
    {
        switch (option)
        {
            case 'N':
                config->count_files = strtoull(optarg, NULL, 0);
                if(config->count_files <= 0)
                {
                    fprintf(stderr, 
                        "[ERROR]: Count of files (-N) cannot be less than 1; provided %d\n", 
                        config->count_files);
                    exit(2);
                }
                break;
            case 'f':
                config->file_to_validate = optarg;
                break;
            case 'k':
                config->file_with_key = optarg;
                break;
            case 'v':
                config->verify_after_sign = true;
                break;
            case 'i':
                config->inputNode = strtoull(optarg, NULL, 0);
                config->inputNode_valid = true;
                break;
            case 'o':
                config->outputNode = strtoull(optarg, NULL, 0);
                config->outputNode_valid = true;
                break;
            case 't':
                config->targetNode = strtoull(optarg, NULL, 0);
                config->targetNode_valid = true;
                break;
            case '?':
            case 'h':
                print_usage(argv[0]);
                break;
            default: CALL_DEBUG_MSG((fprintf(stdout, "option == %d\n", option)));
        }
    }
}

/*TODO: in about 85 years the *nix timers will exceed 32 bit values
 * and some fails may happen.*/
time_t get_time_placeholder()
{
    time_t time_value = time(NULL);
    size_t size = sizeof(time_value);
    time_value |= time_value >> 1;
    time_value |= time_value >> 2;
    time_value |= time_value >> 4;
    if(size > 1)
        time_value |= time_value >> 8;
    if(size > 2)
        time_value |= time_value >> 16;
#ifndef __arm__
    if(size > 4)
        time_value |= time_value >> 32;
#endif
    return ((time_value - (time_value >> 1)));
}

#if RAND_MAX/256 >= 0xFFFFFFFFFFFFFF
  #define LOOP_COUNT 1
#elif RAND_MAX/256 >= 0xFFFFFF
  #define LOOP_COUNT 2
#elif RAND_MAX/256 >= 0x3FFFF
  #define LOOP_COUNT 3
#elif RAND_MAX/256 >= 0x1FF
  #define LOOP_COUNT 4
#else
  #define LOOP_COUNT 5
#endif

uint64_t rand_uint64(void) {
  uint64_t r = 0;
  int i = 0;
  for (i = LOOP_COUNT; i > 0; i--) {
    r = r * (RAND_MAX + (uint64_t)1) + rand();
  }
  return r;
}

int create_data_for_cbor_block(T_cbor_typical_block* cbor_block, T_configuration* config)
{
    int return_value = CSB_OK;
    size_t i = 0;

    cbor_block->input_node = (config->inputNode_valid) ? config->inputNode : rand_uint64();
    cbor_block->output_node = (config->outputNode_valid) ? config->outputNode : rand_uint64();
    cbor_block->target_node = (config->targetNode_valid) ? config->targetNode : rand_uint64();
    cbor_block->not_before = rand_uint64();
    cbor_block->action = rand() % 2;
    cbor_block->type = 0;

    cbor_block->command_count = get_random_in_range(COMMAND_MAX_COUNT);
    for (i = 0; i < cbor_block->command_count; ++i)
        cbor_block->command[i] = rand() % (1 << 16);
    cbor_block->block_heigth = rand_uint64();
    cbor_block->exp = rand_uint64();
    memset(cbor_block->signature, 0xFF, SIGNATURE_LENGTH);
    cbor_block->create_date = time(NULL);
    cbor_block->txn_time = g_time_placeholder;
    return (return_value);
}
#ifdef ENABLE_DEBUG_MSG
void print_debug_info(CborError err, CborEncoder * container)
{
    fprintf(stderr, "error code = %d\n", err);
    if(CborErrorOutOfMemory == err)
        fprintf(stderr, "out of memory\n");
    else if (CborErrorInternalError == err)
        fprintf(stderr, "internal error\n");
   fprintf(stderr, "extra bytes needed: "FORMAT"d\n", cbor_encoder_get_extra_bytes_needed(container));
}
#endif

CborError encode_block_to_cbor(CborEncoder *encoder,
        T_cbor_typical_block *cbor_block,
        uint8_t* buffer,
        T_array_chunk* for_signing)
{
    CborEncoder container;
    CborEncoder arrayEncoder;
    size_t offset_start = 0;
    size_t offset_end = 0;
    if(NULL != for_signing){}
    assert(NULL != encoder);
    assert(NULL != cbor_block);
    CALL_CBOR_ENCODE_FUNCTION((cbor_encoder_create_map(encoder, &container, CBOR_BLOCK_COUNT_ITEMS)), container);
    CALL_DEBUG_MSG((fprintf(stderr, "encoder->container, remaining == "FORMAT"d, used "FORMAT"u bytes\n",
            container.remaining, cbor_encoder_get_buffer_size(&container, buffer))));
    CALL_CBOR_ENCODE_FUNCTION((cbor_encode_text_stringz(&container, names[SIGNATURE_INDEX])), container);
    offset_start = cbor_encoder_get_buffer_size(&container,buffer);
    CALL_CBOR_ENCODE_FUNCTION((cbor_encode_byte_string(&container, cbor_block->signature, SIGNATURE_LENGTH)), container);
    offset_end =  cbor_encoder_get_buffer_size(&container,buffer);
    for_signing[0].start = buffer + offset_start;
    for_signing[0].length = offset_end - offset_start;
    CALL_DEBUG_MSG((fprintf(stderr, "encoder->container, remaining == "FORMAT"d, used "FORMAT"u bytes\n"
            "Offset start == "FORMAT"d, offset end == "FORMAT"d\n",
            container.remaining, cbor_encoder_get_buffer_size(&container, buffer),
            offset_start, offset_end)));
    CALL_CBOR_ENCODE_FUNCTION((cbor_encode_text_stringz(&container, names[TYPE_INDEX])), container);
    CALL_CBOR_ENCODE_FUNCTION((cbor_encode_uint(&container, cbor_block->type)), container);
    CALL_CBOR_ENCODE_FUNCTION((cbor_encode_text_stringz(&container, names[1])), container);
    CALL_CBOR_ENCODE_FUNCTION((cbor_encode_uint(&container, cbor_block->input_node)), container);
    CALL_DEBUG_MSG((fprintf(stderr, "encoder->container, remaining == "FORMAT"d, used "FORMAT"u bytes\n",
            container.remaining, cbor_encoder_get_buffer_size(&container, buffer))));
    CALL_CBOR_ENCODE_FUNCTION((cbor_encode_text_stringz(&container, names[2])), container);
    CALL_CBOR_ENCODE_FUNCTION((cbor_encode_uint(&container, cbor_block->output_node)), container);
    CALL_DEBUG_MSG((fprintf(stderr, "encoder->container, remaining == "FORMAT"d, used "FORMAT"u bytes\n",
            container.remaining, cbor_encoder_get_buffer_size(&container, buffer))));
    CALL_CBOR_ENCODE_FUNCTION((cbor_encode_text_stringz(&container, names[3])), container);
    CALL_CBOR_ENCODE_FUNCTION((cbor_encode_uint(&container, cbor_block->target_node)), container);
    CALL_DEBUG_MSG((fprintf(stderr, "encoder->container, remaining == "FORMAT"d, used "FORMAT"u bytes\n",
            container.remaining, cbor_encoder_get_buffer_size(&container, buffer))));
    CALL_CBOR_ENCODE_FUNCTION((cbor_encode_text_stringz(&container, names[4])), container);
    CALL_CBOR_ENCODE_FUNCTION((cbor_encode_uint(&container, cbor_block->not_before)), container);
    CALL_DEBUG_MSG((fprintf(stderr, "encoder->container, remaining == "FORMAT"d, used "FORMAT"u bytes\n",
            container.remaining, cbor_encoder_get_buffer_size(&container, buffer))));
    CALL_CBOR_ENCODE_FUNCTION((cbor_encode_text_stringz(&container, names[5])), container);
    CALL_CBOR_ENCODE_FUNCTION((cbor_encode_uint(&container, cbor_block->action)), container);
    CALL_DEBUG_MSG((fprintf(stderr, "encoder->container, remaining == "FORMAT"d, used "FORMAT"u bytes\n",
            container.remaining, cbor_encoder_get_buffer_size(&container, buffer))));
    CALL_CBOR_ENCODE_FUNCTION((cbor_encode_text_stringz(&container, names[6])), container);
    CALL_DEBUG_MSG((fprintf(stderr, "encoder->container, remaining == "FORMAT"d, used "FORMAT"u bytes\n",
            container.remaining, cbor_encoder_get_buffer_size(&container, buffer))));
    CALL_CBOR_ENCODE_FUNCTION((cbor_encoder_create_array(&container, &arrayEncoder, cbor_block->command_count)), container);
    CALL_DEBUG_MSG((fprintf(stderr, "encoder->container, remaining == "FORMAT"d, used "FORMAT"u bytes\n",
            container.remaining, cbor_encoder_get_buffer_size(&container, buffer))));
    size_t i = 0;
    CALL_DEBUG_MSG((fprintf(stderr, "command_count == "FORMAT"d\n", cbor_block->command_count)));
    for(i = 0; i < cbor_block->command_count; ++i)
    {
        CALL_DEBUG_MSG((fprintf(stderr, "adding command["FORMAT"d] to CBOR\n", i)));
        CALL_CBOR_ENCODE_FUNCTION((cbor_encode_uint(&arrayEncoder, cbor_block->command[i])), arrayEncoder);
    }
    CALL_CBOR_ENCODE_FUNCTION((cbor_encoder_close_container(&container, &arrayEncoder)), container);
    CALL_DEBUG_MSG((fprintf(stderr, "encoder->container, remaining == "FORMAT"d, used "FORMAT"u bytes\n",
            container.remaining, cbor_encoder_get_buffer_size(&container, buffer))));
    CALL_CBOR_ENCODE_FUNCTION((cbor_encode_text_stringz(&container, names[7])), container);
    CALL_CBOR_ENCODE_FUNCTION((cbor_encode_uint(&container, cbor_block->block_heigth)), container);
    CALL_DEBUG_MSG((fprintf(stderr, "encoder->container, remaining == "FORMAT"d, used "FORMAT"u bytes\n",
            container.remaining, cbor_encoder_get_buffer_size(&container, buffer))));
    CALL_CBOR_ENCODE_FUNCTION((cbor_encode_text_stringz(&container, names[8])), container);
    CALL_CBOR_ENCODE_FUNCTION((cbor_encode_uint(&container, cbor_block->create_date)), container);
    CALL_DEBUG_MSG((fprintf(stderr, "encoder->container, remaining == "FORMAT"d, used "FORMAT"u bytes\n",
            container.remaining, cbor_encoder_get_buffer_size(&container, buffer))));
    CALL_CBOR_ENCODE_FUNCTION((cbor_encode_text_stringz(&container, names[9])), container);
    CALL_CBOR_ENCODE_FUNCTION((cbor_encode_uint(&container, cbor_block->exp)), container);
    CALL_DEBUG_MSG((fprintf(stderr, "encoder->container, remaining == "FORMAT"d, used "FORMAT"u bytes\n",
            container.remaining, cbor_encoder_get_buffer_size(&container, buffer))));
    CALL_CBOR_ENCODE_FUNCTION((cbor_encode_text_stringz(&container, names[10])), container);
    offset_start = cbor_encoder_get_buffer_size(&container,buffer);
    CALL_CBOR_ENCODE_FUNCTION((cbor_encode_uint(&container, cbor_block->txn_time)), container);
    offset_end =  cbor_encoder_get_buffer_size(&container,buffer);
    for_signing[1].start = buffer + offset_start;
    for_signing[1].length = offset_end - offset_start;
    CALL_DEBUG_MSG((fprintf(stderr, "encoder->container, remaining == "FORMAT"d, used "FORMAT"u bytes\n"
            "Offset start == "FORMAT"d, offset end == "FORMAT"d\n",
            container.remaining, cbor_encoder_get_buffer_size(&container, buffer),
            offset_start, offset_end)));

    return cbor_encoder_close_container(encoder, &container);
}

int get_keys(T_keys *key, T_configuration *config)
{
    int return_value = CSB_OK;
    FILE *fp = NULL;
    if((NULL == config->file_with_key) && (NULL == config->file_to_validate))
    {
        if (NULL == (key->eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)))
        {
            CALL_DEBUG_MSG((fprintf(stderr,"Failed to create new EC Key\n")));
            return_value = (CSB_NO_ECKEY);
            goto keygen_err;
        }
        if (1 != (return_value = EC_KEY_generate_key(key->eckey)))
        {
            CALL_DEBUG_MSG((fprintf(stderr,"Failed to generate EC Key\n")));
            goto keygen_err;
        }
        if(1 != EC_KEY_check_key(key->eckey))
        {
            CALL_DEBUG_MSG((fprintf(stderr,"Failed to check EC Key\n")));
            goto keygen_err;
        }
    }
    else
    {
        if (NULL == config->file_with_key)
        {
            if (NULL == (fp = fopen(PUBLIC_KEY_FILE_NAME, "rb")))
            {
                fprintf(stderr,"[ERROR]: Cannot open file %s\n", PUBLIC_KEY_FILE_NAME);
                return (CSB_KEY_FILE_ERROR);
            }
        }
        else
        {
            if (NULL == (fp = fopen(config->file_with_key, "rb")))
            {
                fprintf(stderr,"[ERROR]: Cannot open file %s\n", config->file_with_key);
                return (CSB_KEY_FILE_ERROR);
            }
        }

        if (NULL == config->file_to_validate)
        {
            if(NULL == d2i_ECPrivateKey_fp(fp, &key->eckey))
            {
                fclose(fp);
                fprintf(stderr,"[ERROR]: Cannot read EC private key from file %s.\n", config->file_with_key);
                return (CSB_KEY_FILE_ERROR);
            }
        }
        else
        {
            if(NULL == d2i_EC_PUBKEY_fp(fp, &key->eckey))
            {
                fclose(fp);
                fprintf(stderr,"[ERROR]: Cannot read EC public key from file %s.\n", config->file_with_key);
                return (CSB_KEY_FILE_ERROR);
            }
        }
        fclose(fp);
        if(1 != EC_KEY_check_key(key->eckey))
        {
            fprintf(stderr,"[ERROR]: EC key from file %s is incorrect.\n", config->file_with_key);
            return_value = (CSB_KEY_FILE_ERROR);
            goto keygen_err;
        }
    }

    /* Assign EC_KEY to EVP_PKEY*/
    if (NULL == (key->pkey = EVP_PKEY_new()))
    {
        CALL_DEBUG_MSG((fprintf(stderr,"Failed to create EVP_PKEY\n")));
        return_value = (CSB_NO_EVP_PKEY);
        goto keygen_err;
    }

    if (1 != (return_value = EVP_PKEY_assign_EC_KEY(key->pkey, key->eckey)))
    {
        CALL_DEBUG_MSG((fprintf(stderr,"Failed to assign EC_KEY to EVP_PKEY\n")));
        goto keygen_err;
    }

    if((NULL == config->file_with_key) && (NULL == config->file_to_validate))
    {
        if(NULL == (fp = fopen(PUBLIC_KEY_FILE_NAME, "wb")))
        {
            CALL_DEBUG_MSG((fprintf(stderr,"Failed to create file "PUBLIC_KEY_FILE_NAME"\n")));
            return_value = CSB_FAILED_TO_CREATE_KEY_FILE;
            goto keygen_err;
        }
        if(1 != i2d_EC_PUBKEY_fp(fp, key->eckey))
        {
            fclose(fp);
            CALL_DEBUG_MSG((fprintf(stderr,"Failed to save key to file "PUBLIC_KEY_FILE_NAME"\n")));
            return_value = CSB_FAILED_TO_SAVE_KEY;
            goto keygen_err;
        }
        fclose(fp);

        if(NULL == (fp = fopen(PRIVATE_KEY_FILE_NAME, "wb")))
        {
            CALL_DEBUG_MSG((fprintf(stderr,"Failed to create file "PRIVATE_KEY_FILE_NAME"\n")));
            return_value = CSB_FAILED_TO_CREATE_KEY_FILE;
            goto keygen_err;
        }
        if(1 != i2d_ECPrivateKey_fp(fp, key->eckey))
        {
            fclose(fp);
            CALL_DEBUG_MSG((fprintf(stderr,"Failed to save key to file "PRIVATE_KEY_FILE_NAME"\n")));
            return_value = CSB_FAILED_TO_SAVE_KEY;
            goto keygen_err;
        }
        fclose(fp);
    }

keygen_err:

    if(CSB_OK != return_value)
    {
        EC_KEY_free(key->eckey);
        key->eckey = NULL;
        EVP_PKEY_free(key->pkey);
        key->pkey = NULL;
    }

    return (return_value);
}

int get_signature(uint8_t *signature, size_t *slen, uint8_t *buffer, size_t length, T_keys *key, EVP_MD_CTX* mdctx)
{
    int return_value = -1;

    /* Initialise the DigestSign operation with EVP_MD base on p256v1 EC */
    if(1 != (return_value
            = EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, key->pkey)))
    {
        CALL_DEBUG_MSG((fprintf(stderr, "Failed to set EVP_MD to EVP_PKEY_CTX.\n")));
        return (return_value);
    }

    /* Call update with the message */
    if(1 != (return_value = EVP_DigestSignUpdate(mdctx, buffer, length)))
    {
        CALL_DEBUG_MSG((fprintf(stderr, "Failed to perform EVP_DigestSignUpdate.\n")));
        return (return_value);
    }
    *slen = SIGNATURE_LENGTH;
    /* Obtain the signature */
    if(1 != (return_value = EVP_DigestSignFinal(mdctx, (unsigned char*) (signature), slen)))
    {
        CALL_DEBUG_MSG((fprintf(stderr, "Failed to perform EVP_DigestSignFinal.\n")));
        return (return_value);
    }

    CALL_DEBUG_MSG((print_array(COMMON_DEBUG, stdout, signature, *slen)));

    return return_value;
}

int verify_signature(
        uint8_t *signature_to_be_checked,
        size_t signature_size ,
        uint8_t *buffer,
        size_t buffer_size,
        T_keys *key,
        EVP_MD_CTX *mdctx)
{
    int return_value = 1;
    if(1 != (return_value = EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, key->pkey))) return (return_value);

    /* Initialize `key` with a public key */
    if(1 != (return_value = EVP_DigestVerifyUpdate(mdctx, buffer, buffer_size))) return (return_value);

    if(1 != (return_value = EVP_DigestVerifyFinal(mdctx, signature_to_be_checked, signature_size)))
    {
        return_value = CSB_INCORRECT_SIGNATURE;
        return (return_value);
    }

    return (return_value);
}

int change_signature(
        uint8_t *old_signature,
        size_t *old_signature_len,
        uint8_t* buffer,
        size_t buffer_size,
        uint8_t* signature)
{
    CborParser parser;
    CborValue it;
    CborValue next_it;
    CborEncoder signature_encoder;
    uint8_t* start_signature_buff = NULL;
    uint8_t* end_signature_buff = NULL;
    size_t tmp_signature_len = SIGNATURE_LENGTH;

    assert(NULL != buffer);
    assert(NULL != old_signature);
    assert(NULL != old_signature_len);
    assert(NULL != signature);
    CALL_CBOR_PARSE_FUNCTION((cbor_parser_init (buffer, buffer_size, 0, &parser, &it)));
    CALL_CBOR_PARSE_FUNCTION((cbor_value_validate_basic(&it)));
    CALL_CBOR_CHECK_FUNCTION((cbor_value_at_end(&it)),false, CSB_VALUE_AT_END);
    CALL_CBOR_CHECK_FUNCTION((cbor_value_is_map(&it)),true, CSB_VALUE_NOT_MAP);

    CALL_CBOR_PARSE_FUNCTION((cbor_value_map_find_value(&it, names[SIGNATURE_INDEX], &next_it)));
    CALL_CBOR_CHECK_FUNCTION((cbor_value_get_type(&next_it)), CborByteStringType, CSB_VALUE_NOT_STRING);
    CALL_CBOR_CHECK_FUNCTION((cbor_value_at_end(&next_it)), false, CSB_VALUE_AT_END);
    if(NULL == (start_signature_buff = (uint8_t*)cbor_value_get_next_byte(&next_it))) return CSB_NULL_START_BUFFER;
    CALL_CBOR_PARSE_FUNCTION((cbor_value_copy_byte_string(&next_it, old_signature, &tmp_signature_len, &it)));
    *old_signature_len = old_signature[0];
    CALL_DEBUG_MSG((fprintf(stdout, "Old signature length == "FORMAT"d\n", *old_signature_len)));

    CALL_DEBUG_MSG((fprintf(stdout, "Old signature : \n")));
    CALL_DEBUG_MSG((print_array(COMMON_DEBUG, stdout, old_signature + 1, *old_signature_len)));
    CALL_CBOR_PARSE_FUNCTION((cbor_value_advance(&next_it)));
    if(NULL == (end_signature_buff = (uint8_t*)cbor_value_get_next_byte(&next_it))) return CSB_NULL_END_BUFFER;
    CALL_DEBUG_MSG((fprintf(stdout, "Signature buffer length == "FORMAT"d\n", end_signature_buff - start_signature_buff)));

    cbor_encoder_init(&signature_encoder, start_signature_buff, end_signature_buff - start_signature_buff, 0);
    CALL_CBOR_ENCODE_FUNCTION((cbor_encode_byte_string(&signature_encoder, signature, SIGNATURE_LENGTH)),signature_encoder);

    CALL_CBOR_PARSE_FUNCTION((cbor_parser_init (buffer, buffer_size, 0, &parser, &it)));
    CALL_CBOR_PARSE_FUNCTION((cbor_value_map_find_value(&it, names[TXN_TIME_INDEX], &next_it)));
    CALL_CBOR_CHECK_FUNCTION((cbor_value_get_type(&next_it)), CborIntegerType, CSB_VALUE_NOT_INT);
    if(NULL == (start_signature_buff = (uint8_t*)cbor_value_get_next_byte(&next_it))) return CSB_NULL_START_BUFFER;
    CALL_CBOR_PARSE_FUNCTION((cbor_value_advance(&next_it)));
    if(NULL == (end_signature_buff = (uint8_t*)cbor_value_get_next_byte(&next_it))) return CSB_NULL_END_BUFFER;

    cbor_encoder_init(&signature_encoder, start_signature_buff, end_signature_buff - start_signature_buff, 0);
    CALL_CBOR_ENCODE_FUNCTION((cbor_encode_uint(&signature_encoder, g_time_placeholder)),signature_encoder);
    return (CSB_OK);

}

int load_file(char *file_name, uint8_t* buffer, size_t* buffer_size)
{

    FILE* f = NULL;
    int return_value = CSB_OK;
    /*TODO: get the block from file */
    f = fopen(file_name, "rb");
    if(!f)
    {
        int file_error;
        file_error = errno;
        fprintf(stderr, "[ERROR]: Failed to open file with name %s, error is  %s\n",
                file_name, strerror(file_error));
        return (CSB_FILE_OPEN_FAILED);
    }
    off_t fsize;
    if (fseeko(f, 0, SEEK_END) == 0 && (fsize = ftello(f)) >= 0)
    {
        *buffer_size = fsize;
        if(BUFFER_SIZE < fsize)
            return (CSB_FILE_TOO_BIG);

        rewind(f);
        fsize = fread(buffer, 1, fsize, f);
    }else {
        CALL_DEBUG_MSG((fprintf(stderr, "File with name %s is bigger than %d bytes, usupported.\n", file_name, BUFFER_SIZE)));
        return (CSB_FILE_TOO_BIG);
    }
    fclose(f);
    return (return_value);
}

int create_encode_sign_and_dump_to_file(char *file_name,
        T_keys* key,
        T_times *measurements,
        EVP_MD_CTX* mdctx,
        double** all_times,
        int file_number,
        T_configuration* config)
{
    int return_value = CSB_OK;
    CborEncoder encoder;
    static uint8_t buffer[BUFFER_SIZE] = {};
    size_t cbor_size = 0;
    static uint8_t signature[SIGNATURE_LENGTH];
    size_t signature_len = 0;
    clock_t start_time;
    clock_t stop_time;
    T_array_chunk for_signing[2];

    T_cbor_typical_block cbor_block;
    FILE* f = NULL;
    assert(NULL != file_name);
    memset(buffer, 0xFF, BUFFER_SIZE);
    memset(signature, 0xFF, SIGNATURE_LENGTH);

    start_time = clock();
    return_value = create_data_for_cbor_block(&cbor_block, config);
    stop_time = clock();
    all_times[0][file_number] = (stop_time >= start_time)?(((double)(stop_time - start_time)) / CLOCKS_PER_SEC) : 0;
        measurements[0].avg += all_times[0][file_number];
    if(all_times[0][file_number] > measurements[0].max)
        measurements[0].max = all_times[0][file_number];
    if(all_times[0][file_number] < measurements[0].min)
        measurements[0].min = all_times[0][file_number];
    if(CSB_OK != return_value)
    {
        CALL_DEBUG_MSG((fprintf(stderr, "[ERROR]: Failed to create data for CBOR block.\n")));
        goto err;
    }

    start_time = clock();
    cbor_encoder_init(&encoder, buffer, BUFFER_SIZE, 0);
    CborError err = encode_block_to_cbor(&encoder, &cbor_block, buffer, for_signing);
    cbor_size = cbor_encoder_get_buffer_size(&encoder, buffer);
    stop_time = clock();
    all_times[1][file_number] = (stop_time >= start_time)?(((double)(stop_time - start_time)) / CLOCKS_PER_SEC) : 0;
        measurements[1].avg += all_times[1][file_number];
    if(all_times[1][file_number] > measurements[1].max)
        measurements[1].max = all_times[1][file_number];
    if(all_times[1][file_number] < measurements[1].min)
        measurements[1].min = all_times[1][file_number];
    if (err)
    {
        CALL_DEBUG_MSG((fprintf(stderr, "[ERROR]: Encoding finished with CBOR error %d\n", err)));
        if(CborUnknownError == err)
            return_value = (CBOR_TINY_UNKNOWN_ERROR);
        else
            return_value = err;
        goto err;
    }


    start_time = clock();
    return_value = get_signature(signature + 1, &signature_len, buffer, cbor_size, key, mdctx);
    stop_time = clock();
    all_times[2][file_number] = (stop_time >= start_time)?(((double)(stop_time - start_time)) / CLOCKS_PER_SEC) : 0;
        measurements[2].avg += all_times[2][file_number];
    if(all_times[2][file_number] > measurements[2].max)
        measurements[2].max = all_times[2][file_number];
    if(all_times[2][file_number] < measurements[2].min)
        measurements[2].min = all_times[2][file_number];
    if(CSB_OK != (return_value))
    {
        CALL_DEBUG_MSG((fprintf(stderr, "[ERROR]: Getting signature finished with error %d\n", return_value)));
        goto err;
    }

    if(SIGNATURE_LENGTH - 1 < signature_len)
    {
       fprintf(stderr, "[ERROR]: Expected signature length exceeded %d, necessary to increase SIGNATURE_LENGTH.\n", SIGNATURE_LENGTH - 1);
       return_value = CSB_SIGNATURE_LENGTH_INCREASED;
       goto err;
    }
    else
        signature[0] = (uint8_t)(signature_len & 0xff);
    CALL_DEBUG_MSG((fprintf(stdout, "Signature is \n")));
    CALL_DEBUG_MSG((print_array(COMMON_DEBUG, stdout, signature + 1, signature[0])));
    CALL_DEBUG_MSG((fprintf(stdout, "CBOR block (in hexadecimal form) is (length == "FORMAT"d):\n", cbor_size)));
    CALL_DEBUG_MSG((print_array(COMMON_DEBUG, stdout, buffer, cbor_size)));
    CALL_DEBUG_MSG((fprintf(stdout, "\n")));

    return_value = CSB_OK;
    start_time = clock();
    cbor_encoder_init(&encoder, for_signing[0].start, for_signing[0].length, 0);
    if(CborNoError != (err = cbor_encode_byte_string(&encoder, signature, SIGNATURE_LENGTH))
            && (CSB_OK == return_value))
    {
        CALL_DEBUG_MSG((fprintf(stderr, "[ERROR]: Failed to change signature with error %d\n", return_value)));
        if(CborUnknownError == err)
            return_value = (CBOR_TINY_UNKNOWN_ERROR);
        else
            return_value = err;
    }
    cbor_encoder_init(&encoder, for_signing[1].start, for_signing[1].length, 0);
    if(CborNoError != (err = cbor_encode_uint(&encoder, time(NULL)))
            && (CSB_OK == return_value))
    {
        CALL_DEBUG_MSG((fprintf(stderr, "[ERROR]: Failed to change TXN_date with error %d\n", return_value)));
        if(CborUnknownError == err)
            return_value = (CBOR_TINY_UNKNOWN_ERROR);
        else
            return_value = err;
    }
    stop_time = clock();
    all_times[3][file_number] = (stop_time >= start_time)?(((double)(stop_time - start_time)) / CLOCKS_PER_SEC) : 0;
        measurements[3].avg += all_times[3][file_number];
    if(all_times[3][file_number] > measurements[3].max)
        measurements[3].max = all_times[3][file_number];
    if(all_times[3][file_number] < measurements[3].min)
        measurements[3].min = all_times[3][file_number];
    if(CSB_OK != return_value)
        goto err;

    start_time = clock();
    memset(file_name, 0, OUTPUT_NODE_MAX_LENGTH + 5 + 1);
    if(config->outputNode_valid)
        sprintf(file_name, FORMAT_UINT64"X_%X.cbor", cbor_block.output_node, file_number);
    else
        sprintf(file_name, FORMAT_UINT64"X.cbor", cbor_block.output_node);


    f = fopen(file_name, "wb");

    if(NULL == f)
    {
        int file_error;
        file_error = errno;
        fprintf(stderr, "[ERROR]: Failed to open file with name %s, error is  %s\n",
                file_name, strerror(file_error));
        return_value = (CSB_FILE_OPEN_FAILED);
        goto err;
    }
    else
    {
        fwrite(buffer, 1, cbor_size, f);
        fclose(f);
    }
    stop_time = clock();
    all_times[4][file_number] = (stop_time >= start_time)?(((double)(stop_time - start_time)) / CLOCKS_PER_SEC) : 0;
        measurements[4].avg += all_times[4][file_number];
    if(all_times[4][file_number] > measurements[4].max)
        measurements[4].max = all_times[4][file_number];
    if(all_times[4][file_number] < measurements[4].min)
        measurements[4].min = all_times[4][file_number];
    CALL_DEBUG_MSG((fprintf(stdout, "After writing CBOR file, return value == %d: \n", return_value)));
    CALL_DEBUG_MSG((print_array(COMMON_DEBUG, stdout, buffer, cbor_size)));
err:
    return (return_value);
}

int read_and_verify_cbor_file(char* filename,
        T_keys *key,
        T_times *measurements,
        EVP_MD_CTX* mdctx,
        double** all_times,
        int file_number)
{
    static uint8_t buffer[BUFFER_SIZE];
    size_t buffer_len = 0;
    static uint8_t signature[SIGNATURE_LENGTH];
    static uint8_t signature_zero[SIGNATURE_LENGTH];
    size_t signature_len = 0;
    clock_t start_time;
    clock_t stop_time;
    int return_value = CSB_OK;

    memset(buffer, 0xFF, BUFFER_SIZE);
    memset(signature, 0xFF, SIGNATURE_LENGTH);
    memset(signature_zero, 0xFF, SIGNATURE_LENGTH);

    start_time = clock();
    return_value = load_file(filename, buffer, &buffer_len);
    stop_time = clock();
    all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 0][file_number]
           = (stop_time >= start_time)?(((double)(stop_time - start_time)) / CLOCKS_PER_SEC) : 0;
    measurements[0].avg += all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 0][file_number];
    if(all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 0][file_number] > measurements[0].max)
        measurements[0].max = all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 0][file_number];
    if(all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 0][file_number] < measurements[0].min)
        measurements[0].min = all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 0][file_number];
    if(CSB_OK != (return_value))
    {
        fprintf(stderr, "[ERROR]: Failed to load file with name %s\n", filename);
        goto err;
    }

    assert(0 != buffer_len);

    memset(signature_zero, 0xFF, SIGNATURE_LENGTH);
    start_time = clock();
    return_value
                = change_signature(signature, &signature_len,
                        buffer, buffer_len,
                        signature_zero);
    stop_time = clock();
    all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 1][file_number]
           = (stop_time >= start_time)?(((double)(stop_time - start_time)) / CLOCKS_PER_SEC) : 0;
        measurements[1].avg += all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 1][file_number];
    if(all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 1][file_number] > measurements[1].max)
        measurements[1].max = all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 1][file_number];
    if(all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 1][file_number] < measurements[1].min)
        measurements[1].min = all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 1][file_number];
    if(CSB_OK != (return_value))
    {
        CALL_DEBUG_MSG((fprintf(stderr, "[ERROR]: Failed to change signature with error %d\n", return_value)));
        goto err;
    }

    start_time = clock();
    return_value = verify_signature(signature + 1, signature_len , buffer, buffer_len, key, mdctx);
    stop_time = clock();
    all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 2][file_number]
           = (stop_time >= start_time)?(((double)(stop_time - start_time)) / CLOCKS_PER_SEC) : 0;
        measurements[2].avg += all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 2][file_number] ;
    if(all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 2][file_number]  > measurements[2].max)
        measurements[2].max = all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 2][file_number] ;
    if(all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 2][file_number]  < measurements[2].min)
        measurements[2].min = all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 2][file_number] ;
    if(CSB_OK != (return_value))
    {
        CALL_DEBUG_MSG((fprintf(stderr, "[ERROR]: Signature verification finished with error %d\n", return_value)));
        goto err;
    }
err:
    return (return_value);
}

int main(int argc, char *argv[])
{
    T_configuration config = {0};
    T_keys key = {NULL, NULL};
    char **list_of_files = NULL;
    int return_value = CSB_OK;
    int count_ok = 0;
    int count_wrong = 0;
    T_times validation = {DBL_MAX, 0, 0, 0};
    T_times signing = {DBL_MAX,0,0,0};
    T_times validation_detailed[3] = {{DBL_MAX, 0, 0, 0}, {DBL_MAX, 0, 0, 0}, {DBL_MAX, 0, 0, 0}};
    T_times signing_detailed[5] = {
        {DBL_MAX,0,0, 0}, {DBL_MAX, 0, 0, 0},
        {DBL_MAX,0,0, 0}, {DBL_MAX, 0, 0, 0},
        {DBL_MAX,0,0, 0}};
    double *all_times[TIME_ARRAYS_COUNT] = {NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL};
    clock_t start_time;
    clock_t stop_time;
    int i = 0;
    int j = 0;
    EVP_MD_CTX *mdctx = NULL;

    g_time_placeholder = get_time_placeholder();
    /* Create the Message Digest context*/
    if(!(mdctx = EVP_MD_CTX_create()))
    {
        fprintf(stderr, "[ERROR]: Failed to create MD_CTX object.\n");
        return_value = (2);
        goto err;
    }

    parse_command_line(&config, argc, argv);

    if(CSB_OK != (return_value = get_keys(&key, &config)))
    {
        fprintf(stderr, "[ERROR]: Failed to get or create keys.\n");
        goto err;
    }

    if(NULL == config.file_to_validate)
    {
        srand(clock());
        if(NULL == (list_of_files = malloc(sizeof(char*) * config.count_files)))
        {
            fprintf(stderr, "[ERROR]: Failed to allocate memory.\n");
            return_value = (2);
            goto err;
        }
        for(i = 0; i < TIME_ARRAYS_COUNT; ++i)
        {
            all_times[i] = malloc(sizeof(double) * config.count_files);
            for(j = 0; j < config.count_files; ++j)
                all_times[i][j] = 0.0;
        }

        for(i = 0; i < config.count_files; ++i)
        {
            list_of_files[i] = malloc(sizeof(char*) * (OUTPUT_NODE_MAX_LENGTH + 5 + 1));
            start_time = clock();
            if(CSB_OK != (return_value
                    = create_encode_sign_and_dump_to_file(
                            list_of_files[i], &key, signing_detailed, mdctx, all_times, i, &config)))
                goto err;

            stop_time = clock();
            all_times[5][i] = (stop_time >= start_time)?(((double)(stop_time - start_time)) / CLOCKS_PER_SEC) : 0;
            signing.avg += all_times[5][i];
            if(all_times[5][i] > signing.max)
                signing.max = all_times[5][i];
            if(all_times[5][i] < signing.min)
                signing.min = all_times[5][i];
        }


        if(config.verify_after_sign)
        {
            /*verify the blocks*/
            for(i = 0; i < config.count_files; ++i)
            {
                start_time = clock();
                return_value = read_and_verify_cbor_file(
                        list_of_files[i], &key, validation_detailed, mdctx, all_times, i);
                stop_time = clock();
                all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 3][i]
                             = (stop_time >= start_time)?(((double)(stop_time - start_time)) / CLOCKS_PER_SEC) : 0;
                validation.avg += all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 3][i];
                if(all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 3][i] > validation.max)
                    validation.max = all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 3][i];
                if(all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 3][i] < validation.min)
                    validation.min = all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 3][i];
                if(CSB_OK == (return_value))
                {
                    CALL_DEBUG_MSG((fprintf(stdout, "Signature is OK for file %s\n", list_of_files[i])));
                    ++count_ok;
                }
                else if (CSB_INCORRECT_SIGNATURE == return_value)
                {
                    CALL_DEBUG_MSG((fprintf(stdout, "Signature is WRONG for file %s\n", list_of_files[i])));
                    ++count_wrong;
                }
                else
                    fprintf(stderr, "[ERROR]: Something went wrong during signature validation for file %s, error code %d\n", config.file_to_validate, return_value);
            }
        }
        signing.avg /= config.count_files;
        if(DBL_MAX == signing.min)
            signing.min = 0;
        CALL_DEBUG_MSG((fprintf(stdout, "all_times[%d] before median search:\n", 5)));
        CALL_DEBUG_MSG((print_double_array(1, stdout, all_times[5], config.count_files)));
        signing.median = get_median(all_times[5], config.count_files);
        CALL_DEBUG_MSG((fprintf(stdout, "all_times[%d] before median search:\n", 5)));
        CALL_DEBUG_MSG((print_double_array(1, stdout, all_times[5], config.count_files)));
        for(i = 0; i < TIME_ARRAYS_VERIFICATION_OFFSET - 1; ++i)
        {
            signing_detailed[i].avg /= config.count_files;
            CALL_DEBUG_MSG((fprintf(stdout, "all_times[%d] before median search:\n", i)));
            CALL_DEBUG_MSG((print_double_array(1, stdout, all_times[i], config.count_files)));
            signing_detailed[i].median = get_median(all_times[i], config.count_files);
            CALL_DEBUG_MSG((fprintf(stdout, "all_times[%d] after median search:\n", i)));
            CALL_DEBUG_MSG((print_double_array(1, stdout, all_times[i], config.count_files)));
            if(DBL_MAX == signing_detailed[i].min)
                signing_detailed[i].min = 0;
        }

    }
    else
    {
        config.count_files = 1;
        for(i = 0; i < TIME_ARRAYS_COUNT; ++i)
        {
            all_times[i] = malloc(sizeof(double));
            all_times[i][0] = 0.0;
        }
        start_time = clock();
        return_value = read_and_verify_cbor_file(
                config.file_to_validate, &key, validation_detailed, mdctx, all_times, 0);
        stop_time = clock();
        all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 3][0] = (stop_time >= start_time)?(((double)(stop_time - start_time)) / CLOCKS_PER_SEC) : 0;
        validation.avg = all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 3][0];
        if(all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 3][0] > validation.max)
            validation.max = all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 3][0];
        if(all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 3][0] < validation.min)
            validation.min = all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 3][0];
        if(CSB_OK == (return_value))
        {
            fprintf(stdout, "Signature is OK for file %s\n", config.file_to_validate);
            ++count_ok;
        }
        else if (CSB_INCORRECT_SIGNATURE == return_value)
        {
            fprintf(stdout, "Signature is WRONG for file %s\n", config.file_to_validate);
            ++count_wrong;
        }
        else
            fprintf(stderr, "[ERROR]: Something went wrong during signature validation for file %s, error code %d\n", config.file_to_validate, return_value);
    }

    if((config.verify_after_sign) || (NULL != config.file_to_validate))
    {
        validation.avg /= config.count_files;
        if(DBL_MAX == validation.min)
            validation.min = 0;
        CALL_DEBUG_MSG((fprintf(stdout, "all_times[%d] before median search:\n", TIME_ARRAYS_VERIFICATION_OFFSET + 3)));
        CALL_DEBUG_MSG((print_double_array(1, stdout, all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 3], config.count_files)));
        validation.median = get_median(all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 3], config.count_files);
        CALL_DEBUG_MSG((fprintf(stdout, "all_times[%d] after median search:\n", TIME_ARRAYS_VERIFICATION_OFFSET + 3)));
        CALL_DEBUG_MSG((print_double_array(1, stdout, all_times[TIME_ARRAYS_VERIFICATION_OFFSET + 3], config.count_files)));
        for(i = 0; i < 3; ++i)
        {
            validation_detailed[i].avg /= config.count_files;
            CALL_DEBUG_MSG((fprintf(stdout, "all_times[%d] before median search:\n", TIME_ARRAYS_VERIFICATION_OFFSET + i)));
            CALL_DEBUG_MSG((print_double_array(1, stdout, all_times[TIME_ARRAYS_VERIFICATION_OFFSET +i], config.count_files)));
            validation_detailed[i].median = get_median(all_times[TIME_ARRAYS_VERIFICATION_OFFSET + i], config.count_files);
            CALL_DEBUG_MSG((fprintf(stdout, "all_times[%d] after median search:\n", TIME_ARRAYS_VERIFICATION_OFFSET + i)));
            CALL_DEBUG_MSG((print_double_array(1, stdout, all_times[TIME_ARRAYS_VERIFICATION_OFFSET +i], config.count_files)));
            if(DBL_MAX == validation_detailed[i].min)
                validation_detailed[i].min = 0;
        }
    }
    if(NULL == config.file_to_validate)
    {
        fprintf(stdout, "                  : min        : max        : avg        : median\n"
                        "*Signing total    : %f s : %f s : %f s : %f s.\n",
                        signing.min, signing.max, signing.avg, signing.median);
        fprintf(stdout, "Generating data   : %f s : %f s : %f s : %f s.\n",
                signing_detailed[0].min, signing_detailed[0].max,
                signing_detailed[0].avg, signing_detailed[0].median);
        fprintf(stdout, "Encoding to CBOR  : %f s : %f s : %f s : %f s.\n",
                signing_detailed[1].min, signing_detailed[1].max,
                signing_detailed[1].avg, signing_detailed[1].median);
        fprintf(stdout, "Making signature  : %f s : %f s : %f s : %f s.\n",
                signing_detailed[2].min, signing_detailed[2].max,
                signing_detailed[2].avg, signing_detailed[2].median);
        fprintf(stdout, "Adding signature  : %f s : %f s : %f s : %f s.\n",
                signing_detailed[3].min, signing_detailed[3].max,
                signing_detailed[3].avg, signing_detailed[3].median);
        fprintf(stdout, "Storing file      : %f s : %f s : %f s : %f s.\n",
                signing_detailed[4].min, signing_detailed[4].max,
                signing_detailed[4].avg, signing_detailed[4].median);
    }
    if((config.verify_after_sign) || (NULL != config.file_to_validate))
    {
        fprintf(stdout, "                  : min        : max        : avg        : median\n"
                        "*Validation total : %f s : %f s : %f s : %f s.\n",
                        validation.min, validation.max, validation.avg, validation.median);
        fprintf(stdout, "Loading file      : %f s : %f s : %f s : %f s.\n",
                validation_detailed[0].min, validation_detailed[0].max,
                validation_detailed[0].avg, validation_detailed[0].median);
        fprintf(stdout, "CBOR preparations : %f s : %f s : %f s : %f s.\n",
                validation_detailed[1].min, validation_detailed[1].max,
                validation_detailed[1].avg, validation_detailed[1].median);
        fprintf(stdout, "Verification      : %f s : %f s : %f s : %f s.\n\n",
                validation_detailed[2].min, validation_detailed[2].max,
                validation_detailed[2].avg, validation_detailed[2].median);
        fprintf(stdout, "Signature is correct for %d files.\n" , count_ok);
        fprintf(stdout, "Signature is incorrect for %d files.\n", count_wrong);
    }
err:
    if(NULL != list_of_files)
    {
        for(i = 0; i < config.count_files; ++i)
            CHECK_NULL_AND_FREE(list_of_files[i]);
        CHECK_NULL_AND_FREE(list_of_files);
    }
    for(j = 0; j < TIME_ARRAYS_COUNT; ++j)
        CHECK_NULL_AND_FREE(all_times[j]);

    if(NULL != key.pkey)
    {
        EVP_PKEY_free(key.pkey);
        key.pkey = NULL;
    }
    if(mdctx) EVP_MD_CTX_destroy(mdctx);

    if(CSB_OK == return_value)
        return 0;
    else
    if(0 == return_value)
        return 2;
    else
        return return_value;
}
