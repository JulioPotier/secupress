<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Forked from WPForceSSL
 */
class secupress_ssl_status_tests {

	var $results;
	var $status;
	var $tests;

	public function __construct() {

		$this->status = [ 'success', 'fail' ];

		$this->tests['localhost'] = [
			'title'         => __( 'Localhost Check', 'secupress' ),
			'result'        => [
				'success'   => [
					'title' => __( 'The site is publicly available (not on a localhost)', 'secupress' ),
					'desc'  => __( 'In order to issue a properly signed SSL certificate the site needs to be publicly available.', 'secupress' ),
				],
				'warning'   => [
					'title' => __( 'The site is NOT publicly available. It‘s on a localhost.', 'secupress' ),
					'desc'  => __( 'There is nothing wrong with running a site on localhost. However, some SSL features are not available for localhost.', 'secupress' ),
				],
			]
		];

		$this->tests['sslexpiration'] = [
			'title'         => __( 'SSL Expiration Check', 'secupress' ),
			'result'        => [
				'success'   => [
					'title' => __( 'Your SSL certificate will expire in %1$s days. No need to renew it yet.', 'secupress' ),
					'desc'  => __( 'Having a valid certificate is the first and most important step to having a secure site.', 'secupress' ),
				],
				'warning'   => [
					'title' => __( 'Your SSL certificate will expire in %1$s days. Renew it as soon as possible.', 'secupress' ),
					'desc'  => __( 'It‘s not advisable to renew the certificate at the last minute. We recommend renewing it at least 15 days before it expires.', 'secupress' ),
				],
				'fail'      => [
					'title' => '%1$s',
					'desc'  => __( 'Check your certificate manually immediately.', 'secupress' ),
				],
			]
		];

		$this->tests['sslcertif'] = [
			'title'         => __( 'SSL Certificate Check', 'secupress' ),
			'result'        => [
				'success'   => [
					'title' => __( 'Your SSL certificate is valid', 'secupress' ),
					'desc'  => __( 'Having a valid certificate is the first and most important step to having a secure site.', 'secupress' ),
				],
				'fail'      => [
					'title' => __( 'Your SSL certificate is NOT valid', 'secupress' ),
					'desc'  => __( 'While testing your SSL certificate the following error occurred: %1$s', 'secupress' ),
				],
			]
		];

		$this->tests['httpssupported'] = [
			'title'         => __( 'HTTPS Support Check', 'secupress' ),
			'result'        => [
				'success'   => [
					'title' => __( 'Site address URL is properly configured for HTTPS', 'secupress' ),
					'desc'  => sprintf( __( 'Prefix for the site address URL should be %s', 'secupress' ), secupress_tag_me( 'https://', 'i' ) ),
				],
				'fail'      => [
					'title' => __( 'Site address URL is NOT properly configured', 'secupress' ),
					'desc'  => sprintf( __( 'Site address URL is configured with HTTP instead of HTTPS. Please change the URL in %s.', 'secupress' ), sprintf( '<a href="%s">%s</a>', esc_url( admin_url( 'options-general.php' ) ), __( 'Settings - General', 'secupress' ) ) ),
				],
			]
		];

		$this->tests['httpsredirection'] = [
			'title'         => __( 'HTTP to HTTPS Redirection Check', 'secupress' ),
			'result'        => [
				'success'   => [
					'title' => __( 'Website‘s URLs are properly redirected from HTTP to HTTPS', 'secupress' ),
					'desc'  => sprintf( __( 'URLs like %s are automatically redirected to %s.', 'secupress' ), secupress_code_me( 'http://example.com/page/' ), secupress_code_me( 'https://example.com/page/' ) )
				],
				'fail'      => [
					'title' => __( 'Website‘s URLs are NOT properly redirected from HTTP to HTTPS', 'secupress' ),
					'desc'  => __( 'While testing the redirect the following error occurred: %1$s', 'secupress' ),
				],
			]
		];
	} 

	private function process_tests( $_test_name = '' ) {
		// Get only 1 result
		if ( $_test_name ) {
			$this->tests = [ $_test_name => $this->tests[ $_test_name ] ];
		}

		foreach ( $this->tests as $test_name => $test_details ) {

			$this->result = call_user_func( [ $this, 'test_' . $test_name ] );
			$this->results[ $test_name ] = [
				'title'  => $this->tests[ $test_name ]['title'],
				'status' => $this->result['status'],
				'data'   => $this->result['data'],
			];
		} 
		usort( $this->results, function ($a, $b) {
			$values = array( 'success' => 0, 'fail' => 1);

			if ( $values[ $a['status'] ] === $values[ $b['status'] ] ) {
				return 0;
			}
			return ( $values[ $a['status'] ] > $values[ $b['status'] ] ) ? 1 : -1;
		});

		if ( ! $_test_name ) {
			set_transient( 'secupress_ssl_status', $this->results, DAY_IN_SECONDS );
		}

		return $this->results;
	} 

	public function get_tests_results() {
		if ( ! get_transient( 'secupress_ssl_status' ) ) {
			$this->process_tests();
		}

		return array_combine( array_keys( $this->tests ), $this->results );
	} 


	public function is_localhost() {
		if ( strpos( $_SERVER['SERVER_ADDR'], '127.0.' ) === 0 ||
			 strpos( $_SERVER['SERVER_ADDR'], '192.168.' ) === 0 ||
			( isset( $_SERVER['HTTP_HOST'] ) && $_SERVER['HTTP_HOST'] === 'localhost' ) ||
			$_SERVER['SERVER_ADDR'] === '::1'
		) {
			return true;
		}

		$ssl_status = $this->get_ssl_status( false );
		if ( $ssl_status['error'] && $ssl_status['code'] < 1000 ) {
			return true;
		}

		return false;
	}

	public function get_ssl_status( $skip_cache = false ) {
		if ( $this->is_localhost() ) {
			return [ 'error' => true, 'code' => __LINE__, 'data' => __( 'Server is Localhost', 'secupress' ) ];
		}
		$ssl_status = get_transient( 'secupress_ssl_status_domain' );

		if ( $skip_cache || ! $ssl_status ) {
			$domain = home_url( '/' );

			$ssl_status = [ 'error' => false, 'data' => '' ];

			if ( gethostbyname( $domain ) === $domain ) {
				$ssl_status = [ 'error' => true, 'code' => 1503, 'data' => __( 'Unable to resolve domain name', 'secupress' ) ];
			}

			$response = wp_remote_get( set_url_scheme( $domain, 'https' ) );
			if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
				$err = esc_html( $response['error'] );
				$err = trim( substr( $err, strpos( $err, ':') + 1 ) );
				$err = trim( str_replace( [ 'SSL:', 'SSL certificate problem:' ], '', $err ) );

				$ssl_status = [ 'error' => true, 'code' => __LINE__, 'data' => esc_html( $err ) ];
			} else {
				$g = stream_context_create( [ 'ssl' => [ 'capture_peer_cert' => true ] ] );
				$r = stream_socket_client( "ssl://{$domain}:443", $errno, $errstr, 10, STREAM_CLIENT_CONNECT, $g );
				if ( ! $r ) {
					$ssl_status = [ 'error' => true, 'code' => __LINE__, 'data' => __( 'Unknown error while fetching SSL certificate', 'secupress' ) ];
				} else {
					$cont = stream_context_get_params( $r );
					$tmp  = openssl_x509_parse( $cont['options']['ssl']['peer_certificate'] );
					$data = [];

					$data['valid_from'] = date( 'Y-m-d', (int) $tmp['validFrom_time_t'] );
					$data['valid_to']   = date( 'Y-m-d', (int) $tmp['validTo_time_t'] );
					$data['issuer']     = implode( ', ', array_reverse( $tmp['issuer'] ) );
					$data['issued_to']  = implode( ', ', array_reverse( $tmp['subject'] ) );

					$d = str_ireplace( 'dns:', '', $tmp['extensions']['subjectAltName'] );
					$d = explode( ',', $d );
					$d = array_map( 'trim', $d );

					$data['issued_to_hosts'] = $d;

					$ssl_status = [ 'error' => false, 'code' => 1, 'data' => $data ];
				}
			}

			set_transient( 'secupress_ssl_status_domain', $ssl_status, DAY_IN_SECONDS );
		}

		return $ssl_status;
	} 

	public function test_httpssupported() {
		return [ 'status' => $this->status[ ! secupress_is_https_supported() ], 'data' => '' ];
	} 


	public function test_sslcertif() {
		$ssl_status = $this->get_ssl_status();
		return [ 'status' => $this->status[ $ssl_status['error'] ], 'data' => $ssl_status['data'] ];
	} 


	public function test_localhost() {
		return [ 'status' => $this->status[ $this->is_localhost() ], 'data' => $this->is_localhost() ? __( 'Server is Localhost', 'secupress' ) : '' ];
	} 

	public function test_sslexpiration() {
		if ( $this->is_localhost() ) {
			return [ 'status' => 'fail', 'code' => __LINE__, 'data' => __( 'Server is Localhost', 'secupress' ) ];
		}
		$ssl_status = $this->get_ssl_status();

		if ( $ssl_status['error'] ) {
			return ['status' => 'fail', 'code' => __LINE__, 'data' => __( 'Unable to retrieve the SSL certificate‘s expiration date', 'secupress' ) ];
		} else {
			$days_valid = round( ( strtotime( $ssl_status['data']['valid_to']) - time() ) / DAY_IN_SECONDS);
			if ( $days_valid <= 1 ) {
				return ['status' => 'fail', 'code' => __LINE__, 'data' => __( 'The SSL certificate has expired! Please renew it immediately.', 'secupress' ) ];
			} else {
				return ['status' => 'success', 'code' => __LINE__, 'data' => $days_valid ];
			}
		}
	} 

	public function test_httpsredirection() {
		$home     = home_url( '/?nocache=1', 'http' );
		$response = wp_remote_head( $home );

		if ( is_wp_error( $response ) ) {
			return [ 'status' => 'fail', 'code' => wp_remote_retrieve_response_code( $response ), 'data' => __( 'Unable to retrieve the home page using HTTP request', 'secupress' ) ];
		}
		$target   = wp_remote_retrieve_header( $response, 'location' );

		if ( parse_url( $target, PHP_URL_SCHEME ) === 'https' ) {
			return [ 'status' => 'success', 'code' => 1, 'data' => '' ];
		} else {
			return [ 'status' => 'fail', 'data' => __( 'The website was not redirected to the HTTPS protocol', 'secupress' ) ];
		}
	} 

}
