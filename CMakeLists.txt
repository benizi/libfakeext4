PROJECT ( fakeext4 )

ADD_LIBRARY ( library SHARED libfakeext4.c )
SET_TARGET_PROPERTIES ( library PROPERTIES
  SOVERSION 0
  VERSION 0.0.0
  OUTPUT_NAME fakeext4 )
TARGET_LINK_LIBRARIES ( library dl )

ADD_EXECUTABLE ( wrapper fakeext4.c )
SET_TARGET_PROPERTIES ( wrapper PROPERTIES OUTPUT_NAME fakeext4 )

INSTALL ( TARGETS library LIBRARY DESTINATION lib )
INSTALL ( TARGETS wrapper RUNTIME DESTINATION bin )
