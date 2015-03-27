<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

/**
 * Add submenu in menu "Settings"
 *
 * @since 1.0
 */
add_action( 'admin_menu', 'secupress_create_menus' );
function secupress_create_menus()
{
	add_menu_page( SECUPRESS_PLUGIN_NAME, SECUPRESS_PLUGIN_NAME, 'administrator', 'secupress', '__secupress_dashboard', 'dashicons-shield-alt' );
	add_submenu_page( 'secupress', __( 'Settings', 'secupress' ), __( 'Settings', 'secupress' ), 'administrator', 'secupress_settings', '__secupress_settings' );
	add_submenu_page( 'secupress', __( 'Settings', 'secupress' ), __( 'Modules', 'secupress' ), 'administrator', 'secupress_modules', '__secupress_modules' );
	add_submenu_page( 'secupress', __( 'Scanners', 'secupress' ), __( 'Scanners', 'secupress' ), 'administrator', 'secupress_scanner', '__secupress_scanner' );
}

/**
 * Tell to WordPress to be confident with our setting, we are clean!
 *
 * @since 1.0
 */
add_action( 'admin_init', 'secupress_register_setting' );
function secupress_register_setting()
{
	register_setting( 'secupress_scan', 'secupress' );
}

function __secupress_dashboard() {
	echo '<h1>DASHBOARD</h1>';
	delete_option( SECUPRESS_SCAN_SLUG );
}

function __secupress_modules() {
	echo '<h1>MODULES</h1>';
}

function __secupress_settings() {
	echo '<h1>SETTINGS</h1>';
}


function secupress_field_scan()
{
	global $secupress_tests;
	$scanners = get_option( SECUPRESS_SCAN_SLUG );
	$thedate = ! empty( $scanners['last_run'] ) ? wp_sprintf( __('%s ago'), human_time_diff( $scanners['last_run'] ) ) : __( 'Never', 'secupress' );
	?>
	<a href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_scanner&test=all' ), 'secupress_scanner_all' ); ?>" class="button button-primary button-large button-secupress-scan" style="text-align: center;font-size: 3em; font-style: italic; height: 60px; max-width: 435px; overflow: hidden; padding: 10px 20px; margin-bottom: 5px" id="submit">
			<?php _e( 'Launch Scan', 'secupress' ); ?>
			<span style="clear:both;display:block;line-height:1.6em;font-size: 12px; font-style: italic">
				<?php _e( 'Last scan: ', 'secupress' ); ?><span id="secupress-date"><?php echo $thedate; ?></span>
			</span>
		</a>
	</p>

	<div class="tablenav top hide-if-no-js">

		<div class="alignleft actions bulkactions">
			<label for="bulk-action-selector-top" class="screen-reader-text"><?php _e( 'Select bulk action' ); ?></label>
			<select name="action" id="bulk-action">
				<option value="-1" selected="selected"><?php _e( 'Bulk Actions' ); ?></option>
				<option value="scanit"><?php _e( 'Scan it', 'secupress' ); ?></option>
				<option value="fixit"><?php _e( 'Fix it', 'secupress' ); ?></option>
				<option value="fpositive"><?php _e( 'Mark as False Positive', 'secupress' ); ?></option>
			</select>
			<input type="button" name="" id="doaction" class="button action" value="<?php _e( 'Apply' ); ?>">
		</div>
		<div class="alignleft actions">
			<label for="filter-by-status" class="screen-reader-text"><?php _e( 'Filter by status', 'secupress' ); ?></label>
			<select name="filter-by-status" id="filter-by-status">
				<option selected="selected" value="all"><?php _e( 'All Statuses', 'secupress' ); ?></option>
				<option value="good"><?php _e( 'Good', 'secupress' ); ?></option>
				<option value="bad"><?php _e( 'Bad', 'secupress' ); ?></option>
				<option value="warning"><?php _e( 'Warning', 'secupress' ); ?></option>
				<option value="notscannedyet"><?php _e( 'Not Scanned Yet', 'secupress' ); ?></option>
			</select>
			<input type="button" name="filter_action" id="filter-submit" class="button" value="Filter">
		</div>
		<div class="tablenav-pages one-page">
			<span class="displaying-num">
				<?php printf( __( '%1$d tests in %2$d scanners', 'secupress' ), array_sum( wp_list_pluck( $secupress_tests, 'number_tests' ) ), count( $secupress_tests ) ); ?>
			</span>
		</div>

	</div>

	<div id="secupress-tests">
	<table class="wp-list-table widefat" cellspacing="0" id="table-secupress-tests">
	<thead>
		<tr>
			<th class="secupress-check hide-if-no-js">
				<label class="screen-reader-text" for="cb-select-all"><?php _e( 'Select All' ); ?></label>
				<input id="cb-select-all" type="checkbox" />
			</th>
			<th class="secupress-status"><?php _e( 'Status', 'secupress' ); ?></th>
			<th class="secupress-desc"><?php _e( 'Test Description', 'secupress' ); ?></th>
			<th class="secupress-result"><?php _e( 'Test Results', 'secupress' ); ?></th>
			<th class="secupress-type"><?php _e( 'Test Type', 'secupress' ); ?></th>
		</tr>
	</thead>
	<tbody>
	<?php
	$i=0;
	foreach ( $secupress_tests as $test_name => $details ){
		$i++;
		$status = isset( $scanners[ $test_name ]['status'] ) ? $scanners[ $test_name ]['status'] : secupress_status( /**/'Not Scanned Yet'/**/ ); // Do not localize
		$css_class = isset( $scanners[ $test_name ]['class'] ) && $scanners[ $test_name ]['class'] ? $scanners[ $test_name ]['class'] : 'notscannedyet';
		$class = ' type-' . sanitize_key( $details['type'] );
		$class .= ' status-' . $css_class;
		$class .= $i%2==0 ? '' : ' alternate';
		$scan_title = $css_class != 'notscannedyet' ? __( 'Re-Scan this test', 'secupress' ) : __( 'Scan this test first', 'secupress' );
		$hiddens = !isset( $_GET['DOING_AJAX'] ) ? '' : '<input type="hidden" id="secupress-percent" value="' . $percent . '" /><input type="hidden" id="secupress-humantime" value="' . $thedate . '" />';
		?>
		<tr class="secupress-item-all secupress-item-<?php echo $test_name; ?> type-all status-all<?php echo $class; ?>">
			<td class="secupress-check hide-if-no-js">
				<label class="screen-reader-text" for="cb-select-<?php echo $test_name; ?>"></label>
				<input id="cb-select-<?php echo $test_name; ?>" type="checkbox" />
			</td>
			<td class="secupress-status"><?php echo $hiddens . $status; ?></td>
			<td><?php echo $details['title']; ?>
				<div class="secupress-row-actions">
					<span class="scanit">
						<a href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_scanner&test=' . $test_name ), 'secupress_scanner_' . $test_name ); ?>" class="secupress-scanit" /><?php echo $scan_title; ?></a>
					</span>
					<span class="fixit">
					|	<a href="#" class=" secupress-fixit" title="<?php _e( 'Fix it!', 'secupress' ); ?>" />Fix it</a>
					</span>
					<span class="helpme hide-if-no-js">
					|	<a href="#" class="secupress-details" data-test="<?php echo $test_name; ?>" title="<?php _e( 'Get details', 'secupress' ); ?>" /><span class="edit dashicons dashicons-editor-help"></span></a>
					</span>

				</div>
			</td>
			<td class="secupress-result"><?php echo isset( $scanners[$test_name]['message'] ) ? $scanners[$test_name]['message'] : '&#175;'; ?></td>
			<td><?php echo $details['type']; ?></td>
		</tr>
		<tr id="details-<?php echo $test_name; ?>" class="details hide-if-js" style="background-color:#ddf;">
			<td colspan="4" style="font-style: italic">
				<?php echo $details['details']; ?>
			</td>
		</tr>
		<?php
	}
	?>
	</tbody>
	<tfoot>
		<tr>
			<th class="secupress-check hide-if-no-js">
				<label class="screen-reader-text" for="cb-select-all-2"><?php _e( 'Select All' ); ?></label>
				<input id="cb-select-all-2" type="checkbox" />
			</th>
			<th class="secupress-status"><?php _e( 'Status', 'secupress' ); ?></th>
			<th class="secupress-desc"><?php _e( 'Test Description', 'secupress' ); ?></th>
			<th class="secupress-result"><?php _e( 'Test Results', 'secupress' ); ?></th>
			<th class="secupress-type"><?php _e( 'Test Type', 'secupress' ); ?></th>
		</tr>
	</tfoot>
	</table>
	</div>
	<?php
}

function secupress_status( $status )
{
	$template = '<span class="dashicons dashicons-shield-alt secupress-dashicon secupress-dashicon-color-%2$s"></span> <span class="secupress-status">%1$s</span>';
	switch( $status ):
		case 'Bad': return wp_sprintf( $template, __( 'Bad', 'secupress' ), 'bad' ); break;
		case 'Good': return wp_sprintf( $template, __( 'Good', 'secupress' ), 'good' ); break;
		case 'Warning': return wp_sprintf( $template, __( 'Warning', 'secupress' ), 'warning' ); break;
		default: return wp_sprintf( $template, __( 'Not scanned yet', 'secupress' ), 'notscannedyet' ); break;
	endswitch;
}

function secupress_sidebox( $id, $title, $content, $hideifnojs = false )
{
	$hideifnojs = $hideifnojs ? ' hide-if-no-js' : '';
	return '<div style="width:265px;margin:0 0 10px 0;" class="postbox'.$hideifnojs.'" id="' . $id . '"><h3 style="padding:5px;" class="hndle"><span><b>' . $title . '</b></span></h3> <div class="inside">' . $content . '</div></div>';
}

function __secupress_scanner()
{
	global $current_user, $percent, $secupress_options, $secupress_tests, $scanners;
	require_once( SECUPRESS_FUNCTIONS_PATH . '/secupress_scanner.php' );
	$scanners = (array)get_option( 'secupress' );
	$secupress_options = array_shift( $scanners );
	$good_status = count(array_filter(wp_list_pluck($scanners, 'status'), create_function('$a', 'return $a==__("Good","secupress") ? 1 : 0;')));
	$count_tests = count( $secupress_tests );
	$percent = $count_tests > 0 ? floor( $good_status * 100 / $count_tests ) : 0;

	$all_types = array( 'all'=>_x( 'All', 'security tests', 'secupress' ), 'wordpress'=>__( 'WordPress', 'secupress' ), 'php'=>__( 'PHP', 'secupress' ), 'mysql'=>__( 'MySQL', 'secupress' ), 'files'=>__( 'File System', 'secupress' ) );
	$filter_type = '';
	foreach( $all_types as $k=>$at )
		$filter_type .= sprintf( '<a href="#" data-what="%s" class="filter-type button%s">%s</a> ', $k, get_user_meta( $current_user->ID, 'secupress-type', true )==$k ? ' button-primary' : '', $at );

	$all_status = array( 'all'=>__( 'All', 'secupress' ), 'good'=>__( 'Good', 'secupress' ), 'bad'=>__( 'Bad', 'secupress' ), 'warning'=>__( 'Warning', 'secupress' ), 'notscannedyet'=>__( 'Not Scanned Yet', 'secupress' ) );
	$filter_status = '';
	foreach( $all_status as $k=>$as )
		$filter_status .= sprintf( '<a href="#" data-what="%s" class="filter-status button%s">%s</a> ', $k, get_user_meta( $current_user->ID, 'secupress-status', true )==$k ? ' button-primary' : '', $as );
	$boxes = array( 'score' => array(
						__( 'Score', 'secupress' ),
						'<p style="font-size: 1.5em; font-style: italic;">Your score is ...</p><p><span id="secupress-percentage" style="font-size: 8em; font-style: italic; font-weight: bold; line-height: 0.8em;"><span>' . $percent . '</span> <sub>%</sub></span></p>'
					),
					'premium' => array(
						'SecuPress Security Pro',
						__( 'Get "<b>SecuPress Security Pro</b>" now and fix all to get a Securer installation!<br><a href="#">Clic here</a>', 'secupress' )
					),
					'infos' => array(
						__( 'Informations', 'secupress' ),
					/*////too long*/	sprintf( __( '<p><span class="dashicons dashicons-shield-alt secupress-dashicon-color-good"></span> Good<br /><em>This test has been passed successfully, bravo!</em></p><hr><p><span class="dashicons dashicons-shield-alt secupress-dashicon-color-bad"></span> Bad<br /><em>This test has not been passed successfully, oops!</em></p><hr><p><span class="dashicons dashicons-shield-alt secupress-dashicon-color-warning"></span> Warning<br /><em>This test has been partially passed, try again!</em></p><hr><p><span class="dashicons dashicons-shield-alt secupress-dashicon-color-notscannedyet"></span> Not scanned yet<br /><em>This test has not yet been passed.</em></p>', 'secupress' ), SECUPRESS_PLUGIN_URL )
					),
				);
	$html = '';
	foreach( $boxes as $id => $box ) {
		$html .= secupress_sidebox( $id, $box[0], $box[1], strstr( $id, 'filter' )!==false );
	}
	add_settings_section( 'secupress_scanner', '', '__return_false', 'secupress_scanner' );
		add_settings_field( 'secupress_field_scan', $html, 'secupress_field_scan', 'secupress_scanner', 'secupress_scanner' );

?>
	<div class="wrap">
		<h2><?php echo SECUPRESS_PLUGIN_NAME; ?> <small>v<?php echo SECUPRESS_VERSION; ?></small></h2>
		<?php settings_fields( 'secupress_scanner' ); ?>
		<?php do_settings_sections( 'secupress_scanner' ); ?>
		<?php wp_nonce_field( 'secupress_score', 'secupress_score', false ); ?>
	</div>
<?php
}