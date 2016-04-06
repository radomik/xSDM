#include "main.h"

static FILE* hdrout;
static FILE* in;
static FILE* out;
static void* keyFileName;
static void* unformatted;
static Header* header;
static unsigned char* data;
static unsigned char* input;
static unsigned char* output;
static char* outFile;
static char* sdcDir;
static void* tmp;
static void* dirName;

static int onexit(int retVal)
{
    if (hdrout) fclose(hdrout);
    if (in) fclose(in);
    if (out) fclose(out);
    if (keyFileName) free(keyFileName);
    if (unformatted) free(unformatted);
    if (header) free(header);
    if (data) free(data);
    if (input) free(input);
    if (output) free(output);
    if (outFile) free(outFile);
    if (sdcDir) free(sdcDir);
    if (tmp) free(tmp);
    if (dirName) free(dirName);

    exit(retVal);
    return retVal;
}

int main(int argc, char **argv)
{
    //TODO: get rid of mem leaks (valgrind)
    //For now should be _reliably_ done with manual code analysis/correction
    uint8_t flags = 0;
    const char *sdcFile = NULL;
    int option;
    while((option = getopt_long(argc, argv, "fvH:Vh", options, 0)) != -1)
    {
        switch(option)
        {
        case '?':
            return EXIT_INVALIDOPT;
        //force
        case 'f':
            flags |= F_FORCE;
            break;
        //verbose
        case 'v':
            flags |= F_VERBOSE;
            break;
        //header output
        case 'H':
            print_status("Opening header sink");
            flags |= F_HEADEROUT;
            hdrout = fopen(optarg, "w");
            if(hdrout == NULL)
            {
                //error opening a file
                print_fail();
                // note that perror() here may not print errno from unsuccessful
                // call to fopen() because print_fail() (printf()) may change its
                // value to SUCCESS
                // perror argument type is const char*
                perror(hdrout);
                return onexit(errno);
            }
            print_ok();
            break;
        //version
        case 'V':
            print_version();
            return onexit(EXIT_SUCCESS);
        //help
        case 'h':
            print_help(PH_LONG,argv[0]);
            return onexit(EXIT_SUCCESS);
        default:
            print_help(PH_SHORT,argv[0]);
            return onexit(EXIT_INVALIDOPT);
        }
    }
    if((argc - optind) == 1)
    {
        //parsing argv successful
        sdcFile = argv[optind];
    }
    else
    {
        print_help(PH_SHORT,argv[0]);
        return onexit(EXIT_TOOLESS);
    }

    print_status("Opening SDC file");
    int result;
    in = fopen(sdcFile,"r");
    if(in == NULL)
    {
        //error opening a file
        print_fail();
        perror(sdcFile);
        return onexit(errno);
    }
    print_ok();

    //open key file
    keyFileName = malloc(strlen(sdcFile)+5);
    sprintf((char*)keyFileName,"%s.key",sdcFile);
    FILE *key = fopen((char*)keyFileName,"r");
    if(key == NULL)
    {
        //error opening a file
        print_fail();
        perror((char*)keyFileName);
        return onexit(errno);
    }

    print_status("Verifying keyfile");

    //load keyFileName
    fseek(key,0,SEEK_END);
    int unformattedLength = ftell(key);
    fseek(key,0,SEEK_SET);
    unformatted = malloc(unformattedLength+1);
    fread(unformatted,1,unformattedLength,key);
    ((unsigned char *)unformatted)[unformattedLength] = '\0';
    fclose(key);
    key = NULL;

    //fill unpack structure
    UnpackData unpackData;
    UnpackStatus us = fillUnpackStruct(&unpackData,unformatted);
    switch(us)
    {
    case FUS_OK:
        print_ok();
        break;
    default:
        print_fail();
        fprintf(stderr, "%s: Wrong format of a keyfile!\n", argv[0]);
        return onexit(us);
    }

    //load header size
    union {
        uint8_t  buf[4];
        uint32_t size;
    } hdr;
    fread(hdr.buf,1,4,in);

    print_status("Validating SDC header");

    //check header length
    if(hdr.size < 0xff)
    {
        //it is not length but signature!
        print_fail();
        fprintf(stderr,
              "%s: Encountered unsupported format! Signature is probably "
              "0x%02x\n", argv[0], hdr.size);
        return onexit(-1);
    }

    //load and decode header
    Header *header = (Header*)malloc(hdr.size);
    DecrError err = loadHeader(in, header, hdr.size, &unpackData);
    if(err != DD_OK)
    {
        print_fail();
        fprintf(stderr, "%s: Error when decrypting SDC header (errorcode: %d)\n", argv[0], err);
        return onexit(err);
    }

    //check if valid sdc file
    fseeko(in,0,SEEK_END);
    off_t sdcSize = ftello(in);//FIXME: check if still needed
    if((sizeof(Header) + (sizeof(File) * header->headerSize)) > hdr.size)
    {
        printf("[ FAIL ]\n");
        fprintf(stderr, "%s: File given is not valid SDC file or decryption key wrong\n", argv[0]);
        if(! (flags & F_FORCE))
            return onexit(-1);
    }

    print_ok();

    print_status("Checking file integrity");

    //count crc32
    uLong crc = countCrc(in, hdr.size);
    if(flags & F_VERBOSE)
        fprintf(stderr, "%s: crc32: 0x%08lX; orig: 0x%08X\n", argv[0], crc, unpackData.checksum);

    //check if crc is valid
    if(crc != unpackData.checksum)
    {
        print_fail();
        fprintf(
            stderr, "%s: CRC32 of sdc file did not match the one supplied in keyfile (0x%04X expected while have 0x%04lX)\n",
            argv[0], unpackData.checksum, crc
        );
        if(! (flags & F_FORCE))
            return onexit(crc);
    }
    else
        print_ok();

    FileUnion *current = header->files;
    off_t filestart = hdr.size + 4;
    File *after = &header->files[header->headerSize].file;
    FileName *fn = (FileName*)after;

    print_status("Decoding file name");

    //decode data from header
    uint32_t fnLength = fn->fileNameLength;
    data = (unsigned char*)malloc(getDataOutputSize(fn->fileNameLength) + 1);
    err = decryptData(&fn->fileName, &fnLength, data, unpackData.fileNameKey, 32);
    if(err != DD_OK)
    {
        print_fail();
        fprintf(stderr, "%s: Error while decrypting file name (errorcode: %d)", argv[0], err);
        return onexit(err);
    }
    memcpy((void*)&fn->fileName,data, fnLength);

    print_ok();

    // write decrypted header to file
    if(flags & F_HEADEROUT && hdrout)
    {
        fwrite(&hdr.size, 4, 1, hdrout);
        fwrite(header, hdr.size, 1, hdrout);
        fclose(hdrout);
        hdrout = NULL;
    }

    // unpack files
    output = (unsigned char*)malloc(0x4000);
    int fileid;
    for(fileid = 0; fileid < header->headerSize; fileid++)
    {
        char *filename = (char*)(&fn->fileName);
        filename += current->file.fileNameOffset;
        uint32_t fn_size = strlen(filename);

        if(flags & F_VERBOSE)
            fprintf(stderr,"File path: %s\n",filename);

        dosPathToUnix(filename);

        dirName = realloc(dirName, fn_size + 1);
        strcpy((char*)dirName,filename);
        const char* constDirName = dirname((char*)dirName); // do not free pointer returned by dirname()

        char *baseName = basename(filename);

        //get sdc location
        sdcDir = (char*)realloc(sdcDir, strlen(sdcFile)+1);
        strcpy(sdcDir,sdcFile);
        const char* constSdcDir = dirname(sdcDir);

        print_status("Creating directory structure at '%s'", constDirName);

        //create directory according to header
        outFile = (char*)realloc(outFile, strlen(constSdcDir)+strlen(constDirName)+2);
        sprintf(outFile,"%s/%s",constSdcDir,constDirName);
        int ret = createDir(outFile);
        if(ret != 0)
        {
            print_fail();
            fprintf(stderr,"%s: Directory '%s' creation failed with errno: %d\n",argv[0], outFile,errno);
            return onexit(ret); // exit program on error
        }

        print_ok();

        if(flags & F_VERBOSE)
        {
#define TIMESIZE	20
        char crtime[TIMESIZE];
        time_t creation = winTimeToUnix(current->file.creationTime);
        unixTimeToStr(crtime, TIMESIZE, creation);

        char actime[TIMESIZE];
        time_t access = winTimeToUnix(current->file.accessTime);
        unixTimeToStr(actime, TIMESIZE, access);

        char mdtime[TIMESIZE];
        time_t modification = winTimeToUnix(current->file.modificationTime);
        unixTimeToStr(mdtime, TIMESIZE, modification);

        fprintf(stderr, "File has been originally created at %s, last accessed at %s and modified at %s\n", crtime, actime, mdtime);
        }

        print_status("Unpacking '%s'", baseName);

        //open output file
        outFile = (char*)realloc(outFile, strlen(constSdcDir)+strlen(constDirName)+strlen(baseName)+3);
        sprintf(outFile,"%s/%s/%s",constSdcDir,constDirName,baseName);
        out = fopen(outFile,"w");
        if(out == NULL)
        {
            //error opening a file
            print_fail();
            perror(outFile);
            return onexit(errno);
        }

        //ensure we are after header
        int r;
        if((r = fseek(in,filestart,SEEK_SET))!=0)
            return onexit(r);

        //create inflate struct
        z_stream stream;
        stream.next_in = Z_NULL;
        stream.avail_in = 0;
        stream.zalloc = Z_NULL;
        stream.zfree = Z_NULL;
        stream.opaque = Z_NULL;

        //initialize stream
        r = (int)-1;
        if(header->headerSignature == SIG_ELARGE)
            r = inflateInit(&stream);
        else
            r = inflateInit2_(&stream,-15,ZLIB_VERSION,(int)sizeof(z_stream));
        if(r != Z_OK)
        {
            print_fail();
            fprintf(stderr,"inflateInit failed with errorcode %d (%s)\n",r,stream.msg);
            return onexit(r);
        }
        //read from file
        unsigned int bytesToRead;
        if(header->headerSignature == SIG_ELARGE)
        {
            bytesToRead = current->file4gb.compressedSize & 0x3fff;
        }
        else
        {
            bytesToRead = current->file.compressedSize & 0x3fff;
        }
        input = (unsigned char*)realloc(input, bytesToRead);
        tmp = realloc(tmp, bytesToRead);

        //determine file size
        unsigned int bytesRemaining = 0;
        if(header->headerSignature == SIG_ELARGE)
            bytesRemaining = current->file4gb.fileSize;
        else
            bytesRemaining = current->file.fileSize;
        double fileSize = bytesRemaining, remaining;
        uint8_t progress = 0;

        if(flags & F_VERBOSE)
            fprintf(stderr,"file size has been set as %u (0x%04X), signature: 0x%02X\n",bytesRemaining,bytesRemaining,header->headerSignature);

        while(bytesRemaining != 0)
        {
            // check progress
            remaining = bytesRemaining;
            if((((fileSize - remaining) / fileSize) * 6) > progress)
            {
                ++progress;
                print_progress(progress);
            }

            result = fread(input+stream.avail_in,1,bytesToRead-stream.avail_in,in);
            if(result == 0 && stream.avail_in == 0)	//stop only if stream iflated whole previous buffer
                return onexit(1);				//still have bytes remaining but container end reached

            //decode
            stream.next_in = (Bytef*)input;
            stream.avail_in += result;
            stream.next_out = (Bytef*)output;
            stream.avail_out = 0x4000;
            stream.total_in = 0;
            stream.total_out = 0;
            r = inflate(&stream,0);
            if(r < Z_OK)
            {
                print_fail();
                fprintf(stderr,"inflate failed with errorcode %d (%s)\n",r,stream.msg);
                return onexit(r);
            }

            //XOR
            xorBuffer(unpackData.xorVal % 0x100, output, stream.total_out);

            //write to file
            fwrite(output,1,stream.total_out,out);
            bytesRemaining -= stream.total_out;

            /*
            * tricky part: input buffer hadn't been fully decompressed
            * so we need to copy the rest to TMP and then at the beginning
            * of input buffer so it can be inflated, but before that we need to
            * read the rest of a chunk so its size would be COMPRESSEDSIZE
            */
            memcpy(tmp,stream.next_in,stream.avail_in);
            memcpy(input,tmp,stream.avail_in);
        }

        if(bytesRemaining != 0)
        {
            print_fail();
            fprintf(stderr, "%s: Unexpected end of file!\n", argv[0]);
        }
        else
            print_ok();

        fclose(out);
        out = NULL;

        if(header->headerSignature == SIG_ELARGE)
            filestart += current->file4gb.compressedSize;
        else
            filestart += current->file.compressedSize;
        current++;
    }

    return onexit(0);
}
