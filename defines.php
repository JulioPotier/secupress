<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

define( 'SECUPRESS_VERSION'                   , '2.2' );
define( 'SECUPRESS_MAJOR_VERSION'             , '2.2' );
define( 'SECUPRESS_PATH'                      , realpath( dirname( SECUPRESS_FILE ) ) . DIRECTORY_SEPARATOR );
define( 'SECUPRESS_INC_PATH'                  , SECUPRESS_PATH . 'free' . DIRECTORY_SEPARATOR );
! defined( 'SECUPRESS_API' ) ?
define( 'SECUPRESS_API'                       , 'ab4f63f9ac65152575886860dde480a1' ) : false;
