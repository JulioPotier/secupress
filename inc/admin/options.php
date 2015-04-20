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
	delete_option( SECUPRESS_SCAN_TIMES );
}

function __secupress_modules() {
	echo '<h1>Modules</h1>';
	?>
	<div class="nav-tab-wrapper">
		<ul>
			<li><a href="#tab_user" class="nav-tab nav-tab -active" style="outline: 0px;">Users & Login</a></li>
			<li><a href="#tab_plugin" class="nav-tab" style="outline: 0px;">Plugins & Themes</a></li>
			<li><a href="#tab_cdn" class="nav-tab" style="outline: 0px;">Sensitive Data</a></li>
			<li><a href="#tab_tools" class="nav-tab" style="outline: 0px;">Server Settings</a></li>
			<li><a href="#tab_faq" class="nav-tab" style="outline: 0px;">Backups</a></li>
			<li><a href="#tab_faq" class="nav-tab" style="outline: 0px;">Anti Spam</a></li>
			<li><a href="#tab_support" class="nav-tab file-error" style="outline: 0px;">Common Flaws</a></li>
			<li><a href="#tab_support" class="nav-tab file-error" style="outline: 0px;">Logs</a></li>
			<li><a href="#tab_support" class="nav-tab file-error" style="outline: 0px;">Tools</a></li>
			<li><a href="#tab_support" class="nav-tab file-error" style="outline: 0px;">Schedules</a></li>
		</ul>
		<div id="tab_content">
			<h2>Users and Login Protection</h2>
			<p>Mauris eleifend est et turpis. Duis id erat. Suspendisse potenti. Aliquam vulputate, pede vel vehicula accumsan, mi neque rutrum erat, eu congue orci lorem eget lorem. Vestibulum non ante. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos. Fusce sodales. Quisque eu urna vel enim commodo pellentesque. Praesent eu risus hendrerit ligula tempus pretium. Curabitur lorem enim, pretium nec, feugiat nec, luctus a, lacus.</p>
			<p>Duis cursus. Maecenas ligula eros, blandit nec, pharetra at, semper at, magna. Nullam ac lacus. Nulla facilisi. Praesent viverra justo vitae neque. Praesent blandit adipiscing velit. Suspendisse potenti. Donec mattis, pede vel pharetra blandit, magna ligula faucibus eros, id euismod lacus dolor eget odio. Nam scelerisque. Donec non libero sed nulla mattis commodo. Ut sagittis. Donec nisi lectus, feugiat porttitor, tempor ac, tempor vitae, pede. Aenean vehicula velit eu tellus interdum rutrum. Maecenas commodo. Pellentesque nec elit. Fusce in lacus. Vivamus a libero vitae lectus hendrerit hendrerit.</p>
		</div>
	</div>
	<?php
}

function __secupress_settings() {
	echo '<h1>SETTINGS</h1>';
}


function secupress_main_scan()
{
	global $secupress_tests;
	$scanners = get_option( SECUPRESS_SCAN_SLUG );
	$thedate = ! empty( $scanners['last_run'] ) ? wp_sprintf( __('%s ago'), human_time_diff( $scanners['last_run'] ) ) : __( 'Never', 'secupress' );
	?><!--//
	<a href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_scanner&test=all' ), 'secupress_scanner_all' ); ?>" class="button button-primary button-large button-secupress-scan" style="text-align: center;font-size: 3em; font-style: italic; height: 60px; max-width: 435px; overflow: hidden; padding: 10px 20px; margin-bottom: 5px" id="submit">
		<?php _e( 'Launch Scan', 'secupress' ); ?>
		<span style="clear:both;display:block;line-height:1.6em;font-size: 12px; font-style: italic">
			<?php _e( 'Last scan: ', 'secupress' ); ?><span id="secupress-date"><?php echo $thedate; ?></span>
		</span>
	</a>
//-->

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
	foreach ( $secupress_tests[ $prio_key ] as $test_name => $details ){
		$i++;
		$status = isset( $scanners[ $test_name ]['status'] ) ? $scanners[ $test_name ]['status'] : secupress_status( /**/'Not Scanned Yet'/**/ ); // Do not localize
		$css_class = isset( $scanners[ $test_name ]['class'] ) && $scanners[ $test_name ]['class'] ? $scanners[ $test_name ]['class'] : 'notscannedyet';
		$status_raw = $css_class;
		$class = ' type-' . sanitize_key( $details['type'] );
		$class .= ' status-' . $css_class;
		$class .= $i%2==0 ? ' alternate-2' : ' alternate-1';
		$hiddens = !isset( $_GET['DOING_AJAX'] ) ? '' : '<input type="hidden" id="secupress-percent" value="' . $percent . '" /><input type="hidden" id="secupress-humantime" value="' . $thedate . '" />';
		$points = array( 'good', 'warning', 'bad', 'notscannedyet' );
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
					<a href="#" class="button button-secondary button-small secupress-fixit" title="<?php _e( 'Fix it!', 'secupress' ); ?>" />Fix it</a>
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

function secupress_sidebox( $args )
{
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

function __secupress_scanner()
{
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