/**
 * @version 1.0
 * @author Julio Potier
 */
jQuery(document).ready(function ($){
	$('[type=url][name^=secupress].wp_link_dialog').prop('readonly', true)
		.after( ' <button type="button" class="wp_link_dialog_open secupress-button">' + secupresswplink.insert + '</button>' +
				' <input type="reset" class="wp_link_dialog_reset secupress-button-mini" />' );
	$('[type=reset].wp_link_dialog_reset').click(function (e){
		e.preventDefault();
		var $t = $(this).parent().find('[type=url][name^=secupress].wp_link_dialog');
		$($t).val(secupresswplink.home_url);
	});
	$('button.wp_link_dialog_open').click(function (e){
		$('#link-options, #wplink-link-existing-content').hide();
		var $t = $(this).prev('[type=url][name^=secupress].wp_link_dialog');
		wpLink.open($($t).attr('id'), '', '' );
		wpLink.htmlUpdate = function() {
			var attrs = wpLink.getAttrs();
			var parser = document.createElement( 'a' );
			parser.href = attrs.href;
			if ( 'javascript:' === parser.protocol || 'data:' === parser.protocol ) { // jshint ignore:line
				$($t).val('');
				wpLink.close();
			}
			$($t).val(attrs.href);
			wpLink.close();
		}
	});
})
