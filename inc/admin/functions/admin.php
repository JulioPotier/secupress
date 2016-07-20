<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Display a small page, usually used to block a user until this user provides some info.
 *
 * @since 1.0
 *
 * @param (string) $title   The title tag content.
 * @param (string) $content The page content.
 * @param (array)  $args    Some more data:
 *                 - $head  Content to display in the document's head.
 */
function secupress_action_page( $title, $content, $args = array() ) {
	if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
		return;
	}

	$suffix  = defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ? '' : '.min';
	$version = $suffix ? SECUPRESS_VERSION : time();

	?><!DOCTYPE html>
<html <?php language_attributes(); ?>>
	<head>
		<meta charset="<?php echo esc_attr( strtolower( get_bloginfo( 'charset' ) ) ); ?>" />
		<title><?php echo strip_tags( $title ); ?></title>
		<meta content="initial-scale=1.0" name="viewport" />
		<link href="<?php echo SECUPRESS_ADMIN_CSS_URL . 'secupress-action-page' . $suffix . '.css?ver=' . $version; ?>" media="all" rel="stylesheet" />
		<?php echo ! empty( $args['head'] ) ? $args['head'] : ''; ?>
	</head>
	<body>
		<div class="secupress-action-page-content">
			<?php echo secupress_get_logo( array( 'alt' => SECUPRESS_PLUGIN_NAME, 'width' => 159, 'height' => 155 ) ); ?>
			<?php echo $content; ?>
		</div>
	</body>
</html><?php
	die();
}


/**
 * Add SecuPress informations into USER_AGENT.
 *
 * @since 1.0
 *
 * @param (string) $user_agent A User Agent.
 *
 * @return (string)
 */
function secupress_user_agent( $user_agent ) {
	$bonus  = secupress_is_white_label()        ? '*' : '';
	$bonus .= secupress_get_option( 'do_beta' ) ? '+' : '';
	$new_ua = sprintf( '%s;SecuPress|%s%s|%s|;', $user_agent, SECUPRESS_VERSION, $bonus, esc_url( home_url() ) );

	return $new_ua;
}


/**
 * Used for the "last 5 scans", formate each row.
 *
 * @since 1.0
 *
 * @param (array) $item         An item array containing "percent", "time" and "grade".
 * @param (int)   $last_percent Percentage of the previous item. -1 for the first one.
 *
 * @return (string)
 */
function secupress_formate_latest_scans_list_item( $item, $last_percent = -1 ) {
	$icon = 'minus';

	if ( $last_percent > -1 ) {
		if ( $last_percent < $item['percent'] ) {
			$icon = 'grade-up';
		} elseif ( $last_percent > $item['percent'] ) {
			$icon = 'grade-down';
		}
	}

	return sprintf(
		'<li>
			<span class="secupress-latest-list-time timeago">%3$s</span>
			<span class="secupress-latest-list-date">%4$s</span>
			<strong class="secupress-latest-list-grade letter l%2$s">%2$s</strong>
			<i class="mini icon-%1$s" aria-hidden="true"></i>
		</li>',
		$icon,
		$item['grade'],
		sprintf( __( '%s ago' ), human_time_diff( $item['time'] ) ),
		date_i18n( _x( 'M dS, Y \a\t h:ia', 'Latest scans', 'secupress' ), $item['time'] )
	);
}


/**
 * Return a <table> containing 2 strings displayed with the Diff_Renderer from WP Core.
 *
 * @since 1.0
 *
 * @param (string) $left_string  1st text to compare.
 * @param (string) $right_string 2nd text to compare.
 * @param (array)  $args         An array of arguments (titles).
 *
 * @return (string)
 */
function secupress_text_diff( $left_string, $right_string, $args = array() ) {
	global $wp_local_package;

	if ( ! class_exists( 'WP_Text_Diff_Renderer_Table' ) ) {
		require( ABSPATH . WPINC . '/wp-diff.php' );
	}

	if ( ! class_exists( 'SecuPress_Text_Diff_Renderer_Table' ) ) {

		/**
		 * Table renderer to display the diff lines.
		 *
		 * @since 1.0
		 * @uses WP_Text_Diff_Renderer_Table Extends
		 */
		class SecuPress_Text_Diff_Renderer_Table extends WP_Text_Diff_Renderer_Table {
			/**
			 * Number of leading context "lines" to preserve.
			 *
			 * @var int
			 * @access public
			 * @since 1.0
			 */
			public $_leading_context_lines  = 0;
			/**
			 * Number of trailing context "lines" to preserve.
			 *
			 * @var int
			 * @access public
			 * @since 1.0
			 */
			public $_trailing_context_lines = 0;
		}
	}

	$args         = wp_parse_args( $args, array(
		'title'       => __( 'File Differences', 'secupress' ),
		'title_left'  => __( 'Real file', 'secupress' ),
		'title_right' => __( 'Your file', 'secupress' ),
	) );
	$left_string  = normalize_whitespace( $left_string );
	$right_string = normalize_whitespace( $right_string );
	$left_lines   = explode( "\n", $left_string );
	$right_lines  = explode( "\n", $right_string );
	$text_diff    = new Text_Diff( $left_lines, $right_lines );
	$renderer     = new SecuPress_Text_Diff_Renderer_Table( $args );
	$diff         = $renderer->render( $text_diff );

	if ( $wp_local_package && ( ! $diff || trim( strip_tags( $diff ) ) === '&nbsp;&nbsp;$wp_local_package = \'' . $wp_local_package . '\';' ) ) {
		return __( 'No differences', 'secupress' );
	}

	$r  = "<table class=\"diff\">\n";
		$r .= '<col class="content diffsplit left" /><col class="content diffsplit middle" /><col class="content diffsplit right" />';
		$r .= '<thead>';
			$r .= '<tr class="diff-title"><th colspan="4">' . $args['title'] . "</th></tr>\n";
		$r .= "</thead>\n";
		$r .= '<tbody>';
		$r .= "<tr class=\"diff-sub-title\">\n";
			$r .= "\t<th>" . $args['title_left'] . "</th><td></td>\n";
			$r .= "\t<th>" . $args['title_right'] . "</th><td></td>\n";
		$r .= "</tr>\n";
		$r .= $diff;
		$r .= "</tbody>\n";
	$r .= "</table>\n";

	return $r;
}
