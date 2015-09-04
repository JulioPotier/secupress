<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

add_action( 'admin_head-secupress_page_secupress_settings', 'secupress_favicon' );
add_action( 'admin_head-secupress_page_secupress_modules', 'secupress_favicon' );
add_action( 'admin_head-secupress_page_secupress_scanner', 'secupress_favicon' );
function secupress_favicon() {
	echo '<link id="favicon" rel="shortcut icon" type="image/png" href="' . SECUPRESS_ADMIN_CSS_URL . '/images/black-shield-16.png" />';
}

/**
 * Add submenu in menu "Settings"
 *
 * @since 1.0
 */
add_action( 'admin_menu', 'secupress_create_menus' );
function secupress_create_menus() {
	add_menu_page( SECUPRESS_PLUGIN_NAME, SECUPRESS_PLUGIN_NAME, 'administrator', 'secupress', '__secupress_dashboard', 'dashicons-shield-alt' );
		add_submenu_page( 'secupress', __( 'Settings', 'secupress' ), __( 'Settings', 'secupress' ), 'administrator', 'secupress_settings', '__secupress_global_settings' );
		add_submenu_page( 'secupress', __( 'Modules', 'secupress' ), __( 'Modules', 'secupress' ), 'administrator', 'secupress_modules', '__secupress_modules' );
		add_submenu_page( 'secupress', __( 'Scanners', 'secupress' ), __( 'Scanners', 'secupress' ), 'administrator', 'secupress_scanner', '__secupress_scanner' );
}

function __secupress_modules() {
	global $modulenow, $secupress_modules;

	$modulenow = isset( $_GET['module'] ) ? $_GET['module'] : 'welcome';
	$modulenow = array_key_exists( $modulenow, $secupress_modules ) && file_exists( SECUPRESS_MODULES_PATH . $modulenow . '/settings.php' ) ? $modulenow : 'welcome';
	include(  SECUPRESS_MODULES_PATH . 'UI_menu.php' );
	?>
	<div id="tab_content">
	<?php
		include( SECUPRESS_MODULES_PATH . 'UI_header.php' );
		include( SECUPRESS_MODULES_PATH . $modulenow . '/settings.php' );
		include( SECUPRESS_MODULES_PATH . 'UI_footer.php' );
	?>
	</div>
	<?php
}
/**
 * Tell to WordPress to be confident with our setting, we are clean!
 *
 * @since 1.0
 */
add_action( 'admin_init', 'secupress_register_setting' );
function secupress_register_setting() {
	register_setting( 'secupress_global_settings', SECUPRESS_SETTINGS_SLUG, '__secupress_global_settings_callback' );
}

function __secupress_global_settings_callback( $value ) {
	if ( ! empty( $value['consumer_email'] ) && empty( $value['consumer_key'] ) ) {
		$response = wp_remote_post( SECUPRESS_WEB_DEMO . 'valid_key.php',
						array(
							'timeout' => 10,
							'body'    => array(
								'data' => array(
									'user_email'	=> $value['consumer_email'],
									'user_key'		=> $value['consumer_key'],
									'action'		=> 'create_free_licence',
								)
							),
						)
					);
		if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
			$value['consumer_key'] = wp_remote_retrieve_body( $response );
		}
	}
	return $value;
}

function __secupress_dashboard() {
	$heading_tag = version_compare( $GLOBALS['wp_version'], '4.3' ) >= 0 ? 'h1' : 'h2';
	?>
	<div class="wrap">
		<<?php echo $heading_tag; ?>><?php echo SECUPRESS_PLUGIN_NAME; ?> - <?php _e( 'Dashboard' ); ?></<?php echo $heading_tag; ?>>
	</div>
	<?php
	delete_option( SECUPRESS_SCAN_SLUG );
	delete_option( SECUPRESS_SCAN_TIMES );
}


function __secupress_global_settings() {
	global $modulenow;
	$modulenow = 'global';

	$setting_modules = apply_filters( 'secupress_global_settings_modules', array( 'api-key', 'auto-config' ) );
	foreach ( $setting_modules as $_module) {
		include( SECUPRESS_ADMIN_SETTINGS_MODULES . $_module . '.php' );
	}
	$heading_tag = version_compare( $GLOBALS['wp_version'], '4.3' ) >= 0 ? 'h1' : 'h2';
	?>
	<div class="wrap">
		<<?php echo $heading_tag; ?>><?php echo SECUPRESS_PLUGIN_NAME; ?> <sup><?php echo SECUPRESS_VERSION; ?></sup> <?php _e( 'Settings' ); ?></<?php echo $heading_tag; ?>>
		<form action="options.php" method="post" id="secupress_settings">
			<?php submit_button(); ?>
			<?php settings_fields( 'secupress_settings' ); ?>
			<div class="secupress_setting_block">
				<?php do_settings_sections( 'secupress_apikey' ); ?>
			</div>
			<?php submit_button(); ?>
			<div class="secupress_setting_block">
				<?php do_settings_sections( 'secupress_autoconfig' ); ?>
			</div>
			<?php submit_button(); ?>
		</form>
		<div class="secupress_setting_block">
			<h2><?php _e( 'That\'s all!', 'secupress' ); ?></h2>
			<p><?php _e( 'Looking for more settings? Each other setting is included in its own module, just <a href="#">check them</a> if you need.', 'secupress' ); ?></p>
		</div>
	</div>
	<?php
}

function secupress_uksort_scanners( $key_a, $key_b ) {

}

function secupress_main_scan() {
	global $secupress_tests;
	$scanners = get_option( SECUPRESS_SCAN_SLUG );
	$thedate = ! empty( $scanners['last_run'] ) ? wp_sprintf( __('%s ago'), human_time_diff( $scanners['last_run'] ) ) : __( 'Never', 'secupress' );
	?>
	<a href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_scanner&test=all' ), 'secupress_scanner_all' ); ?>" class="button button-primary button-large button-secupress-scan" style="text-align: center;font-size: 3em; font-style: italic; height: 60px; max-width: 435px; overflow: hidden; padding: 10px 20px; margin-bottom: 5px" id="submit">
		<?php _e( 'One Click Scan', 'secupress' ); ?>
	</a>

	<div class="square-filter priorities hide-if-no-js">
		<span class="active" data-type="all"><?php _ex( 'All Priorities', 'priority', 'secupress' ); ?></span>
		<span data-type="high"><?php _ex( 'High Priority', 'priority', 'secupress' ); ?></span>
		<span data-type="medium"><?php _ex( 'Medium Priority', 'priority', 'secupress' ); ?></span>
		<span data-type="low"><?php _ex( 'Low Priority', 'priority', 'secupress' ); ?></span>
	</div>

	<div class="square-filter statuses hide-if-no-js">
		<span class="active" data-type="all"><?php _ex( 'All Statuses', 'priority', 'secupress' ); ?></span>
		<span data-type="good"><?php _ex( 'Good Status', 'priority', 'secupress' ); ?></span>
		<span data-type="warning"><?php _ex( 'Warning Status', 'priority', 'secupress' ); ?></span>
		<span data-type="bad"><?php _ex( 'Bad Status', 'priority', 'secupress' ); ?></span>
		<span data-type="notscannedyet"><?php _ex( 'Not Scanned Yet', 'priority', 'secupress' ); ?></span>
	</div>

	<div id="secupress-tests">
	<?php
	global $priorities;
	foreach( $priorities as $prio_key => $data ) {
		?>
	<div class="table-prio-all table-prio-<?php echo $prio_key; ?>">
		<div class="prio-<?php echo $prio_key; ?>">
		<h2><?php echo $data['title']; ?></h2>
		<?php echo $data['description']; ?>
		</div>
		<div class="tablenav top hide-if-no-js">

			<div class="alignleft actions bulkactions">
				<label for="bulk-action-selector-top" class="screen-reader-text"><?php _e( 'Select bulk action' ); ?></label>
				<select name="action" id="bulk-action-<?php echo $prio_key; ?>">
					<option value="-1" selected="selected"><?php _e( 'Bulk Actions' ); ?></option>
					<option value="scanit"><?php _e( 'Scan it', 'secupress' ); ?></option>
					<option value="fixit"><?php _e( 'Fix it', 'secupress' ); ?></option>
					<option value="fpositive"><?php _e( 'Mark as False Positive', 'secupress' ); ?></option>
				</select>
				<input type="button" name="" id="doaction-<?php echo $prio_key; ?>" class="button action" value="<?php _e( 'Apply' ); ?>">
			</div>

		</div>


	<table class="wp-list-table widefat" cellspacing="0">
	<thead>
		<tr>
			<th class="secupress-check hide-if-no-js">
				<label class="screen-reader-text" for="cb-select-all"><?php _e( 'Select All' ); ?></label>
				<input id="cb-select-all-<?php echo $prio_key; ?>" type="checkbox" class="me secupress-checkbox-<?php echo $prio_key; ?>"/>
			</th>
			<th class="secupress-status" data-sort="string"><?php _e( 'Status', 'secupress' ); ?></th>
			<th class="secupress-desc"><?php _e( 'Test Description', 'secupress' ); ?></th>
			<th class="secupress-result"><?php _e( 'Test Results', 'secupress' ); ?></th>
			<th class="secupress-fix"><?php _e( 'Fix', 'secupress' ); ?></th>
			<!--// <th class="secupress-type"><?php _e( 'Test Type', 'secupress' ); ?></th> //-->
		</tr>
	</thead>
	<tbody>
	<?php
	$i=0;
	global $statuses_point;
	// uasort( $scanners, function( $a, $b ) {
	// 	$_a = $_b = 2;
	// 	switch ( $a['class'] ) {
	// 		case 'bad': $_a = 1; break;
	// 		case 'good': $_a = 3; break;
	// 	}
	// 	switch ( $b['class'] ) {
	// 		case 'bad': $_b = 1; break;
	// 		case 'good': $_b = 3; break;
	// 	}
	// 	return $_a < $_b ;
	// });
	// var_dump($scanners);
	foreach ( $secupress_tests[ $prio_key ] as $test_name => $details ){
		$i++;
		$status = isset( $scanners[ $test_name ]['status'] ) ? $scanners[ $test_name ]['status'] : secupress_status( /**/'Not Scanned Yet'/**/ ); // Do not localize
		$css_class = isset( $scanners[ $test_name ]['class'] ) && $scanners[ $test_name ]['class'] ? $scanners[ $test_name ]['class'] : 'notscannedyet';
		$status_raw = $css_class;
		$class = ' type-' . sanitize_key( $details['type'] );
		$class .= ' status-' . $css_class;
		$class .= $i%2==0 ? ' alternate-2' : ' alternate-1';
		$hiddens = !isset( $_GET['DOING_AJAX'] ) ? '' : '<input type="hidden" id="secupress-percent" value="' . $percent . '" /><input type="hidden" id="secupress-humantime" value="' . $thedate . '" />';
		$point = array( 'good' => 'd', 'warning' => 'c', 'bad' => 'b', 'notscannedyet' => 'a' );
		$point[ $css_class ] .= $statuses_point[ $css_class ];
		?>
		<tr class="secupress-item-all secupress-item-<?php echo $test_name; ?> type-all status-all<?php echo $class; ?>" data-sort-value="<?php echo $point[ $css_class ]; ?>">
			<td class="secupress-check hide-if-no-js">
				<label class="screen-reader-text" for="cb-select-<?php echo $test_name; ?>"></label>
				<input id="cb-select-<?php echo $test_name; ?>" type="checkbox" class="secupress-checkbox-<?php echo $prio_key; ?>" />
			</td>
			<td class="secupress-status"><?php echo $hiddens . $status; ?></td>
			<td><?php echo $details['title']; ?>
				<div class="secupress-row-actions">
					<span class="rescanit<?php echo $status_raw != 'notscannedyet' ? '' : ' hidden'; ?>">
						<a href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_scanner&prio=' . $prio_key . '&test=' . $test_name ), 'secupress_scanner_' . $test_name ); ?>" class="secupress-scanit" /><?php _e( 'Re-Scan this test', 'secupress' ); ?></a>
					</span>
					<span class="scanit<?php echo $status_raw == 'notscannedyet' ? '' : ' hidden'; ?>">
						<a href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_scanner&prio=' . $prio_key . '&test=' . $test_name ), 'secupress_scanner_' . $test_name ); ?>" class="secupress-scanit" /><?php _e( 'Scan this test first', 'secupress' ) ?></a>
					</span>
					<span class="helpme hide-if-no-js">
					<a href="#" class="secupress-details" data-test="<?php echo $test_name; ?>" title="<?php _e( 'Get details', 'secupress' ); ?>" /><?php _e( 'Learn more', 'secupress' ); ?></a>
					</span>
				</div>
			</td>
			<td class="secupress-result"><?php echo isset( $scanners[$test_name]['message'] ) ? $scanners[$test_name]['message'] : '&#175;'; ?></td>
			<td>
				<span class="fixit<?php echo $status_raw != 'notscannedyet' & $status_raw != 'good' ? '' : ' hide'; ?>">
					<a href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_fixit&prio=' . $prio_key . '&test=' . $test_name ), 'secupress_fixit_' . $test_name ); ?>" class="button button-secondary button-small secupress-fixit" /><?php _e( 'Fix it!', 'secupress' ); ?></a>
				</span>
			</td>
			<!--// <td><?php echo $details['type']; ?></td> //-->
		</tr>
		<tr id="details-<?php echo $test_name; ?>" class="details hide-if-js" style="background-color:#ddf;">
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
			<th class="secupress-check hide-if-no-js">
				<label class="screen-reader-text" for="cb-select-all-2"><?php _e( 'Select All' ); ?></label>
				<input id="cb-select-all-2-<?php echo $prio_key; ?>" type="checkbox" class="me secupress-checkbox-<?php echo $prio_key; ?>"/>
			</th>
			<th class="secupress-status"><?php _e( 'Status', 'secupress' ); ?></th>
			<th class="secupress-desc"><?php _e( 'Test Description', 'secupress' ); ?></th>
			<th class="secupress-result"><?php _e( 'Test Results', 'secupress' ); ?></th>
			<th class="secupress-fix"><?php _e( 'Fix', 'secupress' ); ?></th>
			<!--// <th class="secupress-type"><?php _e( 'Test Type', 'secupress' ); ?></th> //-->
		</tr>
	</tfoot>
	</table>
	</div>
	<?php
	} // foreach prio
	?>
	</div>
	<?php
}

function secupress_status( $status ) {
	$template = '<span class="dashicons dashicons-shield-alt secupress-dashicon secupress-dashicon-color-%2$s"></span> <span class="secupress-status">%1$s</span>';
	switch( $status ):
		case 'Bad': return wp_sprintf( $template, __( 'Bad', 'secupress' ), 'bad' ); break;
		case 'Good': return wp_sprintf( $template, __( 'Good', 'secupress' ), 'good' ); break;
		case 'Warning': return wp_sprintf( $template, __( 'Warning', 'secupress' ), 'warning' ); break;
		default: return wp_sprintf( $template, __( 'Not scanned yet', 'secupress' ), 'notscannedyet' ); break;
	endswitch;
}

function secupress_sidebox( $args ) {
	$defaults = array(
			'id' => '',
			'title' => 'Missing',
			'content' => 'Missing',
			'context' => 'side', // side or top
		);
	$args = wp_parse_args( $args, $defaults );
	$return = '<div class="secupress-postbox postbox" id="' . $args['id'] . '">';
	$return .= '<h3 class="hndle"><span><b>' . $args['title'] . '</b></span></h3>';
	$return .= '<div class="inside">' . $args['content'] . '</div></div>';
	echo $return;
}

function __secupress_scanner() {
	$times = array_filter( (array) get_option( SECUPRESS_SCAN_TIMES ) );
	$reports = array();
	$last_percent = -1;
	foreach ( $times as $time ) {
		$replacement = 'right';
		if ( $last_percent > -1 && $last_percent < $time['percent'] ) {
			$replacement = 'up';
		} else if ( $last_percent > -1 && $last_percent > $time['percent'] ) {
			$replacement = 'down';
		}
		$last_percent = $time['percent'];
		$date = date( 'Y-m-d H:i', $time['time'] + ( get_option( 'gmt_offset' ) * HOUR_IN_SECONDS ) );
		$reports[] = sprintf( '<li data-percent="%1$d"><span class="dashicons mini dashicons-arrow-%2$s-alt2"></span><b>%3$s (%1$d %%)</b> <span class="timeago" title="%4$s">%4$s</span></li>',
								$time['percent'], $replacement, $time['grade'], $date
							);
	}

	$boxes = array( 'score' => array(
						__( 'Your Score', 'secupress' ),
						'<canvas id="status_chart" width="300" height="300"></canvas>' .
						'<div class="score_info2">' .
							'<span class="letter">&ndash;</span>' .
							'<span class="percent">(0 %)</span>' .
							'<span class="score_results"><b>Last Reports</b>:<br>' .
								'<ul>' .
									implode( "\n", array_reverse( $reports ) ) .
								'</ul>' .
							'</span>' .
						'</div>' .
						__( '<div class="legend"><span class="dashicons dashicons-shield-alt secupress-dashicon-color-good"></span> Good | <span class="dashicons dashicons-shield-alt secupress-dashicon-color-bad"></span> Bad | <span class="dashicons dashicons-shield-alt secupress-dashicon-color-warning"></span> Warning | <span class="dashicons dashicons-shield-alt secupress-dashicon-color-notscannedyet"></span> Not scanned yet</div>', 'secupress' ) .
						'<span id="tweeterA" class="hidden"><hr><img style="vertical-align:middle" src="https://g.twimg.com/dev/documentation/image/Twitter_logo_blue_16.png"> <i>' . __( 'Wow! My website just got an A security grade using SecuPress, what about yours?', 'secupress' ) . '</i> <a class="button button-small" href="https://twitter.com/intent/tweet?via=secupress&url=http://secupress.fr&text=' . urlencode( 'Wow! My website just got an A security grade using SecuPress, what about yours?' ) . '">Tweet &raquo;</a></span>'
					),
//					'premium' => array(
//						'SecuPress Security Pro',
//						__( '<img src="https://dl-web.dropbox.com/get/BAW/V3/secupress_sign.png?_subject_uid=45956904&w=AABRKI608fHD9wxoU4qXaJ3TlsmpqTO_vpZT969iKmlrbw"><br>Get "<b>SecuPress Security Pro</b>" now and fix all to get a Securer installation!<br><a href="#">Clic here</a>', 'secupress' )
//					),
//					'infos' => array(
//						__( 'Informations', 'secupress' ),
//					),
				);
?>
	<div class="wrap">
		<h2><?php echo SECUPRESS_PLUGIN_NAME; ?> <small>v<?php echo SECUPRESS_VERSION; ?></small></h2>
		<?php
		foreach( $boxes as $id => $box ) {
			secupress_sidebox( array( 'id' => $id, 'title' => $box[0], 'content' => $box[1], 'context' => 'top' ) );
		}
		?>
		<?php secupress_main_scan(); ?>
		<?php wp_nonce_field( 'secupress_score', 'secupress_score', false ); ?>
	</div>
<?php
}

function secupress_field( $args )
{
	global $modulenow;

	if( ! is_array( reset( $args ) ) ) {
		$args = array( $args );
	}

	$full = $args;
	foreach ( $full as $args ) {
		if ( isset( $args['display'] ) && ! $args['display'] ) {
			continue;
		}
		$args['label_for'] 	= isset( $args['label_for'] ) 	? $args['label_for'] : '';
		$args['name'] 		= isset( $args['name'] ) 		? $args['name'] : $args['label_for'];
		$parent 			= isset( $args['parent'] ) 		? 'data-parent="' . sanitize_html_class( $args['parent' ] ). '"' : null;
		$placeholder 		= isset( $args['placeholder'] )	? 'placeholder="'. $args['placeholder'].'" ' : '';
		$label 				= isset( $args['label'] ) 		? $args['label'] : '';
		$required			= isset( $args['required'] ) 	? ' data-required="required" data-aria-required="true"' : '';
		$pattern			= isset( $args['pattern'] ) 	? ' data-pattern="' . $args['pattern'] . '"' : '';
		$title				= isset( $args['title'] ) 		? ' title="' . $args['title'] . '"' : '';
		$default			= isset( $args['default'] ) 	? $args['default'] : '';
		$cols 				= isset( $args['cols'] ) 		? (int) $args['cols'] : 50;
		$rows 				= isset( $args['rows'] ) 		? (int) $args['rows'] : 5;
		$size 				= isset( $args['size'] ) 		? (int) $args['size'] : 1;
		$readonly			= isset( $args['readonly'] ) && $args['readonly'] ? ' readonly="readonly" disabled="disabled"' : '';
		$class = isset( $args['class'] ) ? $args['class'] : '';
		if ( is_array( $class ) ) {
			$class = implode( ' ', array_map( 'sanitize_html_class', $class ) );
		} else {
			$class = sanitize_html_class( $class );
		}
		$class .= ( $parent ) ? ' has-parent' : null;
		
		if( ! isset( $args['fieldset'] ) || 'start' == $args['fieldset'] ){
			echo '<fieldset class="fieldname-'.sanitize_html_class( $args['name'] ).' fieldtype-'.sanitize_html_class( $args['type'] ).'">';
		}

		switch( $args['type'] ) {
			case 'number' :
			case 'email' :
			case 'text' :

				$value = esc_attr( get_secupress_module_option( $args['name'] ) );
				if ( ! $value ) {
					$value = $default;
				}
				$min = isset( $args['min'] ) ? ' min="' . (int) $args['min'] . '"' : '';
				$max = isset( $args['max'] ) ? ' max="' . (int) $args['max'] . '"' : '';

				$number_options = $args['type']=='number' ? $min . $max . ' class="small-text"' : '';
				$autocomplete = in_array( $args['name'], array( 'consumer_key', 'consumer_email' ) ) ? ' autocomplete="off"' : '';
				$disabled = false ? ' disabled="disabled"' : $readonly;
				$data_realtype = 'password' != $args['type'] ? '' : ' data-realtype="password"';
				?>

					<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
					<label>
						<input <?php echo $title; ?><?php echo $autocomplete; ?><?php echo $pattern; ?><?php echo $required; ?><?php echo $disabled; ?><?php echo $data_realtype; ?> type="<?php echo $args['type']; ?>"<?php echo $number_options; ?> id="<?php echo $args['label_for']; ?>" name="secupress_<?php echo $modulenow; ?>_settings[<?php echo $args['name']; ?>]" value="<?php echo $value; ?>" <?php echo $placeholder; ?><?php echo $readonly; ?>/> 
						<?php echo $label; ?>
					</label>
				<?php
			break;

			case 'password' :

				$value = esc_attr( get_secupress_module_option( $args['name'] ) );
				$data_nocheck = $value ? ' data-nocheck="true"' : '';
				$disabled = false ? ' disabled="disabled"' : $readonly;
				?>

					<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
					<label>
						<input autocomplete="off" data-realtype="password" <?php echo $data_nocheck; ?><?php echo $title; ?><?php echo $pattern; ?><?php echo $required; ?><?php echo $disabled; ?> type="password" id="<?php echo $args['label_for']; ?>" name="secupress_<?php echo $modulenow; ?>_settings[<?php echo $args['name']; ?>]" value="" <?php echo $readonly; ?>/> 
						<input type="text" tabindex="-1" id="password_strength_pattern"<?php echo $data_nocheck; ?> data-pattern="[3-4]" title="<?php _e( 'Minimum Strength Level: Medium', 'secupress' ); ?>" name="secupress_<?php echo $modulenow; ?>_settings[password_strength_value]" value="0" id="password_strength_value" />
						<?php echo $label; ?>
						<i class="hide-if-no-js"><?php printf( __( 'Required: %s', 'secupress' ), _x( 'Medium', 'password strength' ) ); ?></i>
						<br><span id="password-strength" class="hide-if-no-js"></span>
					</label>
				<?php
			break;

			case 'textarea' :

				$t_temp = get_secupress_module_option( $args['name'], '' );
				$value = ! empty( $t_temp ) ? esc_textarea( implode( "\n" , $t_temp ) ) : '';
				if ( ! $value ){
					$value = $default;
				}
				?>

					<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
					<label>
						<textarea id="<?php echo $args['label_for']; ?>" name="secupress_<?php echo $modulenow; ?>_settings[<?php echo $args['name']; ?>]" cols="<?php echo $cols; ?>" rows="<?php echo $rows; ?>"<?php echo $readonly; ?>><?php echo $value; ?></textarea>
					</label>

				<?php
			break;

			case 'checkbox' : 
					if ( isset( $args['label_screen'] ) ) {
					?>
						<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
					<?php } ?>
					<label><input type="checkbox" id="<?php echo $args['name']; ?>" class="<?php echo $class; ?>" name="secupress_<?php echo $modulenow; ?>_settings[<?php echo $args['name']; ?>]" value="1"<?php echo $readonly; ?> <?php checked( get_secupress_module_option( $args['name'], 0 ), 1 ); ?> <?php echo $parent; ?>/> <?php echo $args['label']; ?>
					</label>

			<?php
			break;

			case 'select' : ?>

					<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
					<label>	<select size="<?php echo $args['size']; ?>" multiple="multiple" id="<?php echo $args['name']; ?>" for="<?php echo $args['name']; ?>" name="secupress_<?php echo $modulenow; ?>_settings[<?php echo $args['name']; ?>]"<?php echo $readonly; ?>>
							<?php foreach( $args['options'] as $val => $title) { 
								if ( '_' == $val[0] ) {
									$title .= ' (' . __( 'Premium', 'secupress' ) . ')';
								}
								?>
								<option value="<?php echo $val; ?>" <?php selected( get_secupress_module_option( $args['name'] ) == $val || in_array( $val, get_secupress_module_option( $args['name'], array() ) ) ); ?>><?php echo $title; ?></option>
							<?php } ?>
							</select>
					<?php echo $label; ?>
					</label>

			<?php
			break;

			case 'roles' : 
				$roles = new WP_Roles();
				$roles = $roles->get_names();
				$roles = array_map( 'translate_user_role', $roles );
			?>

					<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
					<?php foreach( $roles as $val => $title) {
						?>
						<label><input type="checkbox" name="secupress_<?php echo $modulenow; ?>_settings[<?php echo $args['name']; ?>][]" value="<?php echo $val; ?>" <?php checked( ! in_array( $val, get_secupress_module_option( $args['name'], array() ) ) ); ?>> <?php echo $title; ?></label><br />
						<input type="hidden" name="secupress_<?php echo $modulenow; ?>_settings[hidden_<?php echo $args['name']; ?>][]" value="<?php echo $val; ?>">
					<?php }
			break;

			case 'checkboxes' : 
			?>

					<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
					<?php foreach( $args['options'] as $val => $title) { 
						if ( '_' == $val[0] ) {
							$title .= ' (' . __( 'Premium', 'secupress' ) . ')';
						}
						?>
						<label><input type="checkbox" for="<?php echo $args['name']; ?>" id="<?php echo $args['name']; ?>_<?php echo $val; ?>" value="<?php echo $val; ?>" <?php checked( in_array( $val, (array) get_secupress_module_option( $args['name'] ) ) ); ?>name="secupress_<?php echo $modulenow; ?>_settings[<?php echo $args['name']; ?>][]"<?php echo $readonly; ?>> <?php echo $title; ?></label><br />
					<?php } ?>

			<?php
			break;	

			case 'radio' : 
			?>

					<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
					<?php foreach( $args['options'] as $val => $title) { 
						if ( '_' == $val[0] ) {
							$title .= ' (' . __( 'Premium', 'secupress' ) . ')';
						}
						?>
						<label><input type="radio" for="<?php echo $args['name']; ?>" id="<?php echo $args['name']; ?>_<?php echo $val; ?>" value="<?php echo $val; ?>" <?php checked( get_secupress_module_option( $args['name'] ), $val ); ?>name="secupress_<?php echo $modulenow; ?>_settings[<?php echo $args['name']; ?>]"<?php echo $readonly; ?>> <?php echo $title; ?></label><br />
					<?php }

			break;

			case 'nonlogintimeslot' : 
			?>

					<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
					<?php 
						$value = get_secupress_module_option( $args['name'] );
						$from_hour = isset( $value['from_hour'] ) ? $value['from_hour'] : '';
						$from_minute = isset( $value['from_minute'] ) ? $value['from_minute'] : '';
						$to_hour = isset( $value['to_hour'] ) ? $value['to_hour'] : '';
						$to_minute = isset( $value['to_minute'] ) ? $value['to_minute'] : '';

						_e( 'Everyday', 'secupress' ); ////
						echo '<br>';
						echo '<span style="display:inline-block;min-width:3em">' . _x( 'From', '*From* xx h xx mn To xx h xx mn', 'secupress' ) . '</span>';
						?>
						<label><input type="number" class="small-text" min="0" max="23" id="<?php echo $args['name']; ?>_from_hour" value="<?php echo (int) $from_hour; ?>" name="secupress_<?php echo $modulenow; ?>_settings[<?php echo $args['name']; ?>][from_hour]"<?php echo $readonly; ?>> </label> <?php _ex( 'h', 'hour', 'secupress' ); ?>
						<label><input type="number" class="small-text" min="0" max="45" step="15" id="<?php echo $args['name']; ?>_from_minute" value="<?php echo (int) $from_minute; ?>" name="secupress_<?php echo $modulenow; ?>_settings[<?php echo $args['name']; ?>][from_minute]"<?php echo $readonly; ?>></label> <?php _ex( 'min', 'minute', 'secupress' ); ?>
						<br>
						<?php
						echo '<span style="display:inline-block;min-width:3em">' . _x( 'To', 'From xx h xx mn *To* xx h xx mn', 'secupress' ) . '</span>';
						?>
						<label><input type="number" class="small-text" min="0" max="23" id="<?php echo $args['name']; ?>_to_hour" value="<?php echo (int) $to_hour; ?>" name="secupress_<?php echo $modulenow; ?>_settings[<?php echo $args['name']; ?>][to_hour]"<?php echo $readonly; ?>> </label> <?php _ex( 'h', 'hour', 'secupress' ); ?>
						<label><input type="number" class="small-text" min="0" max="45" step="15" id="<?php echo $args['name']; ?>_to_minute" value="<?php echo (int) $to_minute; ?>" name="secupress_<?php echo $modulenow; ?>_settings[<?php echo $args['name']; ?>][to_minute]"<?php echo $readonly; ?>></label> <?php _ex( 'min', 'minute', 'secupress' ); ?>
						<?php

			break;

			case 'helper_description' :

				$description = isset( $args['description'] ) ? '<p class="description desc '.$class.'">'.$args['description'].'</p>' : '';
				echo apply_filters( 'secupress_help', $description, $args['name'], 'description' );

			break;

			case 'helper_help' :
				$description = isset( $args['description'] ) ? '<p class="description help '.$class.'">'.$args['description'].'</p>' : '';
				echo apply_filters( 'secupress_help', $description, $args['name'], 'help' );

			break;

			case 'helper_warning' :

				$description = isset( $args['description'] ) ? '<p class="description warning '.$class.'"><b>'.__( 'Warning: ', 'secupress') . '</b>' . $args['description'].'</p>' : '';
				echo apply_filters( 'secupress_help', $description, $args['name'], 'warning' );

			break;
/*
			case 'secupress_export_form' :
				?>
				<a href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_export' ), 'secupress_export' ); ?>" id="export" class="button button-secondary secupressicon"><?php _e( 'Download options', 'secupress' ); ?></a>
				<?php
			break;

			case 'secupress_import_upload_form' :

				secupress_import_upload_form( 'secupress_importer' );

			break;*/
			default : 'Type manquant ou incorrect'; // ne pas traduire

		}

		if( ! isset( $args['fieldset'] ) || 'end' == $args['fieldset'] ) {
			echo '</fieldset>';
		}

	}

}

/**
 * Used to display buttons on settings form, tools tab
 *
 * @since 1.0
 */
function secupress_button( $args )
{
	$button       = $args['button'];
	$desc         = isset( $args['helper_description'] ) ? $args['helper_description'] : null;
	$help         = isset( $args['helper_help'] ) ? $args['helper_help'] : null;
	$warning      = isset( $args['helper_warning'] ) ? $args['helper_warning'] : null;
	$id           = isset( $button['button_id'] ) ? sanitize_html_class( $button['button_id'] ) : null;
	$class        = sanitize_html_class( strip_tags( $button['button_label'] ) );
	$button_style = isset( $button['style'] ) ? 'button-'.sanitize_html_class( $button['style'] ) : 'button-secondary';

	if ( ! empty( $help ) ) {
		$help = '<p class="description help '.$class.'">'.$help['description'].'</p>';
	}
	if ( ! empty( $desc ) ) {
		$desc = '<p class="description desc '.$class.'">'.$desc['description'].'</p>';
	}
	if ( ! empty( $warning ) ) {
		$warning = '<p class="description warning file-error '.$class.'"><b>'.__( 'Warning: ', 'secupress' ) . '</b>' . $warning['description'].'</p>';
	}
?>
	<fieldset class="toto fieldname-<?php echo $class; ?> fieldtype-button">
		<?php
		if ( isset( $button['url'] ) ) {
			echo '<a href="' . esc_url( $button['url'] ) . '" id="' . $id . '" class="' . $button_style . ' secupressicon secupressicon-'. $class . '">' . wp_kses_post( $button['button_label'] ) . '</a>';
		} else {
			echo '<button id="' . $id . '" class="' . $button_style . ' secupressicon secupressicon-'. $class . '">' . wp_kses_post( $button['button_label'] ) . '</button>';
		}
		?>
		

		<?php echo apply_filters( 'secupress_help', $desc, sanitize_key( strip_tags( $button['button_label'] ) ), 'description' ); ?>
		<?php echo apply_filters( 'secupress_help', $help, sanitize_key( strip_tags( $button['button_label'] ) ), 'help' ); ?>
		<?php echo apply_filters( 'secupress_help', $warning, sanitize_key( strip_tags( $button['button_label'] ) ), 'warning' ); ?>

	</fieldset>
<?php
}

