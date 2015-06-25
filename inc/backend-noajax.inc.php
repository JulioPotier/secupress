<?php
if( !defined( 'ABSPATH' ) )
	die( 'Cheatin\' uh?' );

add_filter( 'plugin_action_links_' . plugin_basename( SECUPRESS_FILE ), 'secupress_settings_action_links' );
function secupress_settings_action_links( $links )
{
	array_unshift( $links, '<a href="' . admin_url( 'admin.php?page=secupress_scan' ) . '">' . __( 'Scan' ) . '</a>' );
	return $links;
}

// add_action( 'admin_notices', 'secupress_admin_notice_warn' );
function secupress_admin_notice_warn()
{
	if( !$secupress_options = get_option( 'secupress' ) )
		echo '<div class="error below-h2 secupress-neverrun"><p>' . wp_sprintf( __( '<strong>SecuPress Security</strong> scan was never run. Click "<a href="%s">%s</a>" to scan now and analyze this WordPress installation for security flaws.', 'secupress' ), admin_url( 'admin.php?page=secupress_scan' ), __( 'Launch Scan', 'secupress' ) ) . '</p></div>';
	elseif( $secupress_options['options']['version'] != SECUPRESS_VERSION )
		echo '<div class="error below-h2 secupress-oldversion"><p>' . wp_sprintf( __( '<strong>SecuPress Security</strong> scan was never run with this new version %s (old version %s). Click "<a href="%s">%s</a>" to scan now and analyze this WordPress installation again.', 'secupress' ), SECUPRESS_VERSION, esc_html( $secupress_options['options']['version'] ), admin_url( 'admin.php?page=secupress_scan' ), __( 'Launch Scan', 'secupress' ) ) . '</p></div>';
}

function secupress_admin_notice_bad_request()
{
	echo '<div class="error below-h2 secupress-badrequest"><p>' . _e( '<strong>SecuPress Security</strong>: Bad request ...', 'secupress' ) . ' </p></div>';
}
		
add_action( 'admin_menu', 'secupress_create_menus' );
function secupress_create_menus()
{
	add_menu_page( SECUPRESS_FULLNAME, SECUPRESS_FULLNAME, 'administrator', 'secupress', '__secupress_dashboard', 'dashicons-shield-alt' );
	add_submenu_page( 'secupress', __( 'Scanner', 'secupress' ), __( 'Scanner', 'secupress' ), 'administrator', 'secupress_scanner', '__secupress_scanner' );
	register_setting( 'secupress_scan', 'secupress' );
}

function __secupress_dashboard() {
	echo '<h1>DASHBOARD</h1>';
}


add_action( 'load-tools_page_secupress_scan', 'secupress_scan_nojs' );
function secupress_scan_nojs()
{
	if( isset( $_REQUEST['this_test'], $_REQUEST['_secupressnonce'], $_REQUEST['action'] ) ):
		require( dirname( __FILE__ ) . '/backend-ajax.inc.php' );
		secupress_launch_scan( $_REQUEST['this_test'], $_REQUEST['_secupressnonce'], $_REQUEST['action'] );
	endif;	
	if( isset( $_REQUEST['type'], $_REQUEST['status'], $_REQUEST['_secupressnonce'] ) ):
		global $current_user;
		wp_verify_nonce( $_REQUEST['_secupressnonce'], 'secupress_scan-options' ) or wp_nonce_ays('');
		update_user_meta( $current_user->ID, 'secupress-type', sanitize_key( $_REQUEST['type'] ) );
		update_user_meta( $current_user->ID, 'secupress-status', sanitize_key( $_REQUEST['status'] ) );
		die();
	endif;
}

add_action( 'admin_print_scripts-tools_page_secupress_scan', 'secupress_enqueue_scripts' );
function secupress_enqueue_scripts()
{
	wp_enqueue_script( 'secupress-js', SECUPRESS_PLUGIN_URL . 'js/secupress.js', null, SECUPRESS_VERSION, true );
	// wp_enqueue_style( 'sn-css', SECUPRESS_PLUGIN_URL . 'css/secupress.css', null, SECUPRESS_VERSION );
}

function secupress_field_scan()
{
	global $percent, $secupress_options, $secupress_tests, $secupress_tests_saved;
	// $last_scan_date = !empty( $secupress_options['last_run'] ) ? date_i18n( get_option( 'date_format' ), $secupress_options['last_run'] ) : __( 'Never', 'secupress' );
	// $last_scan_time = !empty( $secupress_options['last_run'] ) ? date_i18n( get_option( 'time_format' ), $secupress_options['last_run'] ) : __( 'please do...', 'secupress' );;
	$thedate = !empty( $secupress_options['last_run'] ) ? wp_sprintf( __('%s ago'), human_time_diff( $secupress_options['last_run'] ) ) : __( 'Never', 'secupress' );
	?>

	<p>
		<button data-nonce="<?php echo wp_create_nonce( 'scan-test_all' ); ?>" style="font-family: georgia; font-size: 3em; font-style: italic; height: 60px; max-width: 435px; overflow: hidden; padding: 0 20px;" data-test="all" class="button button-primary button-large button-scan" id="submit" name="submit">
			<?php _e( 'Launch Scan', 'secupress' ); ?>
			<span style="clear:both;display:block;line-height:1.6em;font-size: 12px; font-style: italic"><?php _e( 'Last scan: ', 'secupress' ); ?><span id="secupress-date"><?php echo $thedate; ?></span></span>
		</button>
	</p>
	
	<div id="div-secupress-security">
	<table class="wp-list-table widefat" cellspacing="0" id="table-secupress-security">
	<thead>
		<tr>
			<th class="secupress-status"><?php _e( 'Status', 'secupress' ); ?></th>
			<th><?php _e( 'Test Description', 'secupress' ); ?></th>
			<th><?php _e( 'Test Results', 'secupress' ); ?></th>
			<th><?php _e( 'Test Type', 'secupress' ); ?></th>
			<th><?php _e( 'Actions', 'secupress' ); ?></th>
		</tr>
	</thead>
	<tbody>
	<?php
	$i=0;
	foreach( $secupress_tests as $test_name => $details ){
	$i++;
	$class = ' type-' . sanitize_key( $details['type'] );
	$class .= ' status-' . sanitize_key( isset( $secupress_tests_saved[$test_name]['status'] ) ? $secupress_tests_saved[$test_name]['status'] : /**/'Not Scanned Yet'/**/ ); // Do not localize
	$class .= $i%2==0 ? ' alternate' : '';
	$hiddens = !isset( $_GET['DOING_AJAX'] ) ? '' : '<input type="hidden" id="secupress-percent" value="' . $percent . '" /><input type="hidden" id="secupress-humantime" value="' . $thedate . '" />';
	?>
	<tr class="secupressitem-all secupressitem-<?php echo $test_name; ?> type-all status-all<?php echo $class; ?>">
		<td class="secupress-status"><?php echo $hiddens . secupress_status( isset( $secupress_tests_saved[$test_name]['status'] ) ? $secupress_tests_saved[$test_name]['status'] : -1 ); ?></td>
		<td><?php echo $details['title']; ?></td>
		<td><?php echo isset( $secupress_tests_saved[$test_name]['message'] ) ? $secupress_tests_saved[$test_name]['message'] : '---'; ?></td>
		<td><?php echo $details['type']; ?></td>
		<td>
			<p id="secupress-actions">
				<button type="button" class="button-secondary secupress-fixit"><?php _e( 'Fix it!', 'secupress' ); ?></button>
				<a href="<?php echo admin_url( 'tools.php?page=secupress_scan&action=scan&this_test=' . $test_name . '&_secupressnonce=' . wp_create_nonce( 'scan-test_' . $test_name ) ); ?>" data-nonce="<?php echo wp_create_nonce( 'scan-test_' . $test_name ); ?>" data-test="<?php echo $test_name; ?>" class="button secupress-fixit" title="Refresh this test" style="background: transparent url(<?php echo SECUPRESS_PLUGIN_URL; ?>/img/scan.png) no-repeat 2px 2px;height:24px;width:18px;" /></a>
				<a href="#" class="hide-if-no-js button secupress-details" data-test="<?php echo $test_name; ?>" title="<?php _e( 'Get details', 'secupress' ); ?>" style="background: transparent url(<?php echo SECUPRESS_PLUGIN_URL; ?>/img/details.png) no-repeat 2px 2px;height:24px;width:18px;" /></a>
			</p>
		</td>
	</tr>
	<tr id="details-<?php echo $test_name; ?>" class="hide-if-js" style="background-color:#ddf;">
		<td colspan="5" style="font-style: italic">
			<?php echo $details['details']; ?>
		</td>
	</tr>
	<?php
	}
	?>
	</tbody>
	<tfoot>
		<tr>
			<th class="secupress-status"><?php _e( 'Status', 'secupress' ); ?></th>
			<th><?php _e( 'Test Description', 'secupress' ); ?></th>
			<th><?php _e( 'Test Results', 'secupress' ); ?></th>
			<th><?php _e( 'Test Type', 'secupress' ); ?></th>
			<th><?php _e( 'Actions', 'secupress' ); ?></th>
		</tr>
	</tfoot>
	</table>
	</div>
	<?php
}

function secupress_status( $status )
{
	$template = '<span class="%1$s"><img src="' . SECUPRESS_PLUGIN_URL . 'img/shield_%3$s.png" title="%2$s" /> %2$s</span>';
	switch( $status ):
		case 'Bad': return wp_sprintf( $template, 'secupress-bad', __( 'Bad', 'secupress' ), 'bad' ); break;
		case 'Good': return wp_sprintf( $template, 'secupress-good', __( 'Good', 'secupress' ), 'good' ); break;
		case 'Warning': return wp_sprintf( $template, 'secupress-warning', __( 'Warning', 'secupress' ), 'warning' ); break;
		default: return wp_sprintf( $template, 'secupress-notyet', __( 'Not scanned yet', 'secupress' ), 'notscannedyet' ); break;
	endswitch;
}

function secupress_setting_box( $id, $title, $content, $hideifnojs = false )
{
	$hideifnojs = $hideifnojs ? ' hide-if-no-js' : '';
	return '<div style="width:265px;margin:0 0 10px 0;" class="postbox'.$hideifnojs.'" id="' . $id . '"><h3 style="padding:5px;" class="hndle"><span><b>' . $title . '</b></span></h3> <div class="inside">' . $content . '</div></div>';
}

function __secupress_scanner()
{
	global $current_user, $percent, $secupress_options, $secupress_tests, $secupress_tests_saved;
	require_once( dirname( __FILE__ ) . '/secupress-tests.inc.php' );
	$secupress_tests_saved = (array)get_option( 'secupress' );
	$secupress_options = array_shift( $secupress_tests_saved );
	$good_status = count(array_filter(wp_list_pluck($secupress_tests_saved, 'status'), create_function('$a', 'return $a==__("Good","secupress") ? 1 : 0;')));
	$count_tests = count( $secupress_tests );
	$percent = $count_tests>0 ? floor( $good_status * 100 / $count_tests ) : 0;

	$all_types = array( 'all'=>_x( 'All', 'security tests', 'secupress' ), 'wordpress'=>__( 'WordPress', 'secupress' ), 'php'=>__( 'PHP', 'secupress' ), 'mysql'=>__( 'MySQL', 'secupress' ), 'files'=>__( 'File System', 'secupress' ) );
	$filter_type = '';
	foreach( $all_types as $k=>$at )
		$filter_type .= sprintf( '<a href="#" data-what="%s" class="filter-type button%s">%s</a> ', $k, get_user_meta( $current_user->ID, 'secupress-type', true )==$k ? ' button-primary' : '', $at );

	$all_status = array( 'all'=>__( 'All', 'secupress' ), 'good'=>__( 'Good', 'secupress' ), 'bad'=>__( 'Bad', 'secupress' ), 'warning'=>__( 'Warning', 'secupress' ), 'notscannedyet'=>__( 'Not Scanned Yet', 'secupress' ) );
	$filter_status = '';
	foreach( $all_status as $k=>$as )
		$filter_status .= sprintf( '<a href="#" data-what="%s" class="filter-status button%s">%s</a> ', $k, get_user_meta( $current_user->ID, 'secupress-status', true )==$k ? ' button-primary' : '', $as );
	$boxes = array( 'score' => array( __( 'Score', 'secupress' ), '<p style="font-family: georgia; font-size: 1.5em; font-style: italic;">Your score is ...</p><p><span id="secupress-percentage" style="font-family: georgia; font-size: 8em; font-style: italic; font-weight: bold; line-height: 0.8em;"><span>' . $percent . '</span> <sub>%</sub></span></p>' ),
					'premium' => array( 'SecuPress Security Pro', __( 'Get "<b>SecuPress Security Pro</b>" now and fix all to get a Securer installation!<br><a href="#">Clic here</a>', 'secupress' ) ),
					'filter_type' => array( __( 'Filter by type', 'secupress' ), '<p data-who="type">' . $filter_type . '</p>' ),
					'filter_status' => array( __( 'Filter by status', 'secupress' ), '<p data-who="status">' . $filter_status . '</p>' ),
					'infos' => array( __( 'Informations', 'secupress' ), wp_sprintf( __( '<p><img src="%1$s/img/shield_good.png" title="Good" /> Good<br /><em>This test has been passed successfully, bravo!</em></p><hr><p><img src="%1$s/img/shield_bad.png" title="Bad" /> Bad<br /><em>This test has not been passed successfully, oops!</em></p><hr><p><img src="%1$s/img/shield_warning.png" title="Warning" /> Warning<br /><em>This test has been partially passed, try again!</em></p><hr><p><img src="%1$s/img/shield_notscannedyet.png" title="Not scanned yet" /> Not scanned yet<br /><em>This test has not yet been passed.</em></p>', 'secupress' ), SECUPRESS_PLUGIN_URL ) ),
					);
	$html = '';
	foreach( $boxes as $id => $box )
		$html .= secupress_setting_box( $id, $box[0], $box[1], strstr( $id, 'filter' )!==false );
	add_settings_section( 'secupress_scanner', '', '__return_false', 'secupress_scan' );
		add_settings_field( 'secupress_field_scan', $html, 'secupress_field_scan', 'secupress_scan', 'secupress_scanner' );

?>
	<div class="wrap">
		<div id="icon-secupress" class="icon32" style="background: url(<?php echo SECUPRESS_PLUGIN_URL; ?>img/icon32.png) 0 0 no-repeat;"><br/></div> 
		<h2><?php echo SECUPRESS_FULLNAME; ?> <small>v<?php echo SECUPRESS_VERSION; ?></small></h2>

		<form action="admin-post.php?page=secupress_scanner&" method="post">
			<?php settings_fields( 'secupress_scan' ); ?>
			<?php do_settings_sections( 'secupress_scan' ); ?>
			<input type="hidden" name="this_test" value="all" />
			<?php wp_nonce_field( 'scan-test_all', '_secupressnonce', false ); ?>
		</form>
	</div>
<?php
}