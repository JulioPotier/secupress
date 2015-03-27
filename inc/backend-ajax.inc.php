<?php
if( !defined( 'ABSPATH' ) )
	die( 'Cheatin\' uh?' );

add_action( 'wp_ajax_secupress_launch_scan', 'secupress_launch_scan' );
function secupress_launch_scan( $this_test = null, $nonce = null, $action = null )
{
	$this_test = isset( $_REQUEST['this_test'] ) ? $_REQUEST['this_test'] : $this_test;
	$nonce = isset( $_REQUEST['_secupressnonce'] ) ? $_REQUEST['_secupressnonce'] : $nonce;
	$action = isset( $_REQUEST['action'] ) ? $_REQUEST['action'] : $action;
	$results = get_option( 'secupress' );

	if( !empty( $this_test ) && !empty( $nonce ) && !empty( $action ) ):
		wp_verify_nonce( $nonce, 'scan-test_' . $this_test ) or wp_nonce_ays('');
		$results['options'] = array( 'last_run' => current_time( 'timestamp', true ), 'version'=>SPS_VERSION );
		require_once( dirname( __FILE__ ) . '/secupress-tests.inc.php' );
		require_once( dirname( __FILE__ ) . '/secupress-functions.inc.php' );
		foreach( $secupress_tests as $test_name => $test ):
			@set_time_limit(0);
			if( ( $this_test == null || $this_test == 'all' || $this_test == $test_name ) && function_exists( 'secupress_' . $test_name ) ):
				ob_start();
					$t = 'secupress_' . $test_name;
					$response = @$t();
				ob_end_flush();
				$results[$test_name]['status'] = $response['status'];
				$results[$test_name]['message'] = wp_sprintf( $test['msg_'.sanitize_key($response['status'])], isset( $response['message'] ) ? $response['message'] : '' );
			endif;
		endforeach;
		update_option( 'secupress', $results );
		if( defined( 'DOING_AJAX' ) && DOING_AJAX )
			die( '1' );
		else
			wp_redirect( admin_url( 'admin.php?page=secupress_scanner' ) );
	else:
		if( defined( 'DOING_AJAX' ) && DOING_AJAX )
			die( '-1' );
		else
			add_action( 'admin_notices', 'secupress_admin_notice_bad_request' );
	endif;
}
