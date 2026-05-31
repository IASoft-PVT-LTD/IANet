find_package(Doxygen)
find_package(Python3 COMPONENTS Interpreter)

if(DOXYGEN_FOUND AND Python3_FOUND AND NOT TARGET ianet-docs)
    add_custom_target(ianet-docs
        COMMAND ${Python3_EXECUTABLE} -m mkdocs build
            -f ${IANET_ROOT}/docs/mkdocs.yml
        WORKING_DIRECTORY ${IANET_ROOT}/docs
        COMMENT "Building MkDocs site (mkdoxy API + prose)"
    )
    add_custom_target(ianet-docs-serve
        COMMAND ${Python3_EXECUTABLE} -m mkdocs serve
            -f ${IANET_ROOT}/docs/mkdocs.yml
        WORKING_DIRECTORY ${IANET_ROOT}/docs
        COMMENT "Serve MkDocs site locally"
    )
endif()
