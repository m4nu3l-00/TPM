cmake_minimum_required(VERSION 3.0.0)

project(cryptTest)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)

include_directories("/usr/local/lib")
include_directories("/usr/local/openssl3.0/include")
include_directories("/usr/local/openssl3.0/lib64")
include_directories("/usr/local/openssl3.0/lib64/engines-3")

file(GLOB SOURCE_FILES "*.cpp" )

file(GLOB HEADER_FILES "*.h" )


link_directories(
	"."
	"/usr/local/openssl3.0/lib64"
	"/usr/local/openssl3.0/lib64/engines-3"
	"/usr/local/lib"
	)


source_group("Source" FILES ${SOURCE_FILES})
source_group("Header" FILES ${HEADER_FILES})

add_executable(genCrypto ${SOURCE_FILES} ${HEADER_FILES} )

if (${WINDOWS})
	# set_target_properties (genCrypto PROPERTIES LINK_FLAGS "/NODEFAULTLIB:MSVCRT")
else()
	# nothing
endif()

#target_link_libraries(
#genCrypto
#)

if (${WINDOWS})
	
else()
	target_link_libraries(
		genCrypto
		tss2-fapi
		tss2-rc
		tss2-esys
        crypto
        ssl
		stdc++)
endif()

# add_dependencies(genCrypto )
