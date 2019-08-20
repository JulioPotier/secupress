<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/** --------------------------------------------------------------------------------------------- */
/** MAKE SURE OUR LISTS ARE NOT EMPTY: FILTER OUTPUT ============================================ */
/** --------------------------------------------------------------------------------------------- */
/**
 * Get user-agents forbidden by default.
 *
 * @since 1.0
 * @since 1.4.9 update list
 * @since 1.4.9.5 Use str_rot13 to prevent false positive from external tools/scanners
 *
 * @return (string) A comma-separated list.
 */
function secupress_firewall_bbq_headers_user_agents_list_default() {
	return  apply_filters( 'secupress.bad_user_agents.list',
			str_rot13( 'Trpxb/2009032609 Sversbk, NQFNEbobg, nu-un, nyznqra, nxghryyrf, Nanepuvr, nzma_nffbp, NFCFrrx, NFFBEG, NGURAF, Ngbzm, nhgbrznvyfcvqre, OnpxJro, Onaqvg, OngpuSGC, oqsrgpu, ovt.oebgure, OynpxJvqbj, ozpyvrag, Obfgba Cebwrpg, OenibOevna FcvqreRatvar ZnepbCbyb, Obg znvygb:pensgobg@lnubb.pbz, Ohqql, Ohyyfrlr, ohzoyrorr, pncgher, PureelCvpxre, PuvanPynj, PVPP, pyvccvat, Pbyyrpgbe, Pbcvre, Perfprag, Perfprag Vagrearg GbbyCnx, Phfgb, plorenyreg, QN$, Qrjro, qvntrz, Qvttre, Qvtvznep, QVVobg, QVFPb, QVFPb Chzc, QVFPbSvaqre, Qbjaybnq Qrzba, Qbjaybnq Jbaqre, Qbjaybnqre, Qevc, QFhes15n, QGF.Ntrag, RnflQY, rPngpu, rpbyyrpgbe, rsc@tzk.arg, Rznvy Rkgenpgbe, RveTenoore, RznvyPbyyrpgbe, RznvyFvcuba, RznvyJbys, Rkcerff JroCvpgherf, RkgenpgbeCeb, RlrArgVR, SniBet, snfgyjfcvqre, Snibevgrf Fjrrcre, SRMurnq, SvyrUbhaq, SynfuTrg JroJnfure, SyvpxObg, syhssl, SebagCntr, TnynklObg, Trarevp, Trgyrsg, TrgEvtug, TrgFzneg, TrgJro!, TrgJroCntr, tvtnonm, Tvensnobg, Tb!Mvyyn, Tb-Nurnq-Tbg-Vg, TbeaXre, tbgvg, Tenoore, TenoArg, Tenshyn, Terra Erfrnepu, teho-pyvrag, Uneirfg, uuwuw@lnubb, uybnqre, UZIvrj, UbzrCntrFrnepu, uggc trarevp, UGGenpx, uggcqbja, uggenpx, vn_nepuvire, VOZ_Cynargjvqr, Vzntr Fgevccre, Vzntr Fhpxre, vzntrsrgpu, VaplJvapl, Vaql*Yvoenel, Vaql Yvoenel, vasbeznag, Vatryva, VagreTRG, Vagrearg Avawn, VagreargYvaxntrag, VagreargFrre.pbz, Vevn, Veivar, WOU*ntrag, WrgPne, WBP, WBP Jro Fcvqre, WhfgIvrj, XJroTrg, Ynpurfvf, yneova, YrrpuSGC, YrkvObg, ysgc, yvojjj, yvxfr, Yvax*Fyrhgu, YVAXF NEbZNGVMRQ, YvaxJnyxre, YJC, yjc-gevivny, Znt-Arg, Zntarg, Znp Svaqre, Znff Qbjaybnqre, ZPfcvqre, Zrzb, Zvpebfbsg.HEY, ZVQbja gbby, Zveebe, Zvffvthn Ybpngbe, Zvfgre CvK, ZZZgbPenjy/HeyQvfcngpureYYY, ^Zbmvyyn$, Zbmvyyn.*Vaql, Zbmvyyn.*ARJG, Zbmvyyn*ZFVRPenjyre, ZF SebagCntr*, ZFSebagCntr, ZFVRPenjyre, ZFCebkl, zhygvguernqqo, angvbanyqverpgbel, Aniebnq, ArneFvgr, ArgNagf, ArgPnegn, ArgZrpunavp, argcebfcrpgbe, ArgErfrnepuFreire, ArgFcvqre, Arg Inzcver, ArgMVC, ArgMvc Qbjaybnqre, ArgMvccl, ARJG, AVPRefCEB, Avawn, ACObg, Bpgbchf, Bssyvar Rkcybere, Bssyvar Anivtngbe, BcnY, Bcrasvaq, BcraGrkgFvgrPenjyre, CntrTenoore, Cncn Sbgb, CnpxEng, cnihx, cpOebjfre, CrefbanCvybg, CvatNYvax, Cbpxrl, cfobg, CFhes, chs, Chzc, ChfuFvgr, DEIN, ErnyQbjaybnq, Erncre, Erpbeqre, ErTrg, ercynpre, ErcbZbaxrl, Ebobmvyyn, Ebire, ECG-UGGCPyvrag, Eflap, Fpbbgre, FrnepuRkcerff, frnepuuvccb, frnepugrezf.vg, Frpbaq Fgerrg Erfrnepu, Frrxre, Funv, Fvcuba, fvgrpurpx, fvgrpurpx.vagreargfrre.pbz, FvgrFanttre, FylFrnepu, FznegQbjaybnq, fanttre, Fanxr, FcnprOvfba, Fcrtyn, FcvqreObg, fcebbfr, FdJbez, Fgevccre, Fhpxre, FhcreObg, FhcreUGGC, Fhesobg, FhesJnyxre, Fmhxnpm, gNxrBhg, gnefcvqre, Gryrcbeg Ceb, Grzcyrgba, GehrEbobg, GI33_Zrepngbe, HVbjnPenjyre, HgvyZvaq, HEYFcvqreCeb, HEY_Fcvqre_Ceb, Inphhz, intnobaqb, inlnyn, ivfvovyvgltnc, IbvqRLR, ifcvqre, Jro Qbjaybnqre, j3zve, Jro Qngn Rkgenpgbe, Jro Vzntr Pbyyrpgbe, Jro Fhpxre, Jjro, JroNhgb, JroOnaqvg, jro.ol.znvy, Jropyvccvat, jropbyyntr, jropbyyrpgbe, JroPbcvre, jropensg@orn, jroqrivy, jroqbjaybnqre, Jroqhc, JroRZnvyRkgenp, JroSrgpu, JroTb VF, JroUbbx, Jrovangbe, JroYrnpure, JROZNFGREF, JroZvare, JroZveebe, jrozbyr, JroErncre, JroFnhtre, Jrofvgr, Jrofvgr rKgenpgbe, Jrofvgr Dhrfgre, JroFanxr, Jrofgre, JroFgevccre, jrofhpxre, jroinp, jrojnyx, jrojrnfry, JroJunpxre, JroMVC, Junpxre, juvmonat, JubfGnyxvat, Jvqbj, JVFRobg, JJJBSSYR, k-Genpgbe, ^Knyqba JroFcvqre, JHZCHF, Krah, KTRG, Mrhf.*Jrofgre, Mrhf, furyy, erzbgrivrj, onfr64_, ova/onfu, qvfpbaarpg, riny, yjc-qbjaybnq, hafrevnyvmr, 360Fcvqre, npncobg, npbbaobg, nyrkvobg, nfgrevnf, nggnpxobg, onpxqbeobg, orpbzrobg, ovayne, oynpxjvqbj, oyrxxbobg, oyrkobg, oybjsvfu, ohyyfrlr, ohaalf, ohggresyl, pnerreobg, pnfcre, purpxcevi, purrfrobg, pureelcvpx, puvanpynj, pubccl, pyfuggc, pzfjbeyq, pbcreavp, pbclevtugpurpx, pbfzbf, perfprag, pl_pub, qngnpun, qrzba, qvniby, qvfpbobg, qvggbfclqre, qbgobg, qbgargqbgpbz, qhzobg, rznvypbyyrpgbe, rznvyfvcuba, rznvyjbys, rkgenpg, rlrargvr, srrqsvaqre, synzvat, synfutrg, syvpxl, sbbobg, t00t1r, trgevtug, tvtnobg, tb-nurnq-tbg, tbmvyyn, tenoarg, tenshyn, uneirfg, urevgevk, vpnehf6w, wrgobg, wrgpne, wvxrfcvqre, xzpperj, yrrpusgc, yvojro, yvaxrkgenpgbe, yvaxfpna, yvaxjnyxre, ybnqre, zvare, znwrfgvp, zrpunavmr, zbesrhf, zbirbireobg, argzrpunavp, argfcvqre, avprefceb, avxgb, avawn, ahgpu, bpgbchf, cntrtenoore, cynargjbex, cbfgenax, cebkvzvp, cherobg, clphey, clguba, dhrela, dhrelfrrxre, enqvna6, enqvngvba, ernyqbjaybnq, ebtreobg, fpbbgre, frrxrefcvqre, frznyg, fvpyno, fvaqvpr, fvfgevk, fvgrobg, fvgrrkcybere, fvgrfanttre, fxltevq, fznegqbjaybnq, fabbcl, fbfbfcvqre, fcnaxobg, fcobg, fdyznc, fgnpxenzoyre, fgevccre, fhpxre, fhesgobg, fhk0e, fhmhxnpm, fhmhena, gnxrbhg, gryrcbeg, gryrfbsg, gehr_ebobgf, ghevatbf, gheavg, inzcver, ivxfcvqre, ibvqrlr, jroyrnpure, jroerncre, jrofgevccre, jroivrjre, jrojunpxre, jvauggc, jjjbssyr, jbkobg, knyqba, kkkll, lnznanyno, lvbbcobg, lbhqn, mrhf, mzrh, mhar, mlobet' )
			);
}

/**
 * Get contents forbidden in URL by default.
 *
 * @since 1.0
 * @since 1.4.9 update list
 * @since 1.4.9.5 Use str_rot13 to prevent false positive from external tools/scanners
 *
 * @return (string) A comma-separated list.
 */
function secupress_firewall_bbq_url_content_bad_contents_list_default() {
	// We cut some words to prevent being tagged as "bad" file from scanners.
	return  apply_filters( 'secupress.bad_url_contents.list',
			str_rot13( 'NAQ%201=, vasbezngvba_fpurzn, HAVBA%20FRYRPG, HAVBA%20NYY%20FRYRPG, riny(, jc-pbasvt, %%30%30, TYBONYF[, .vav, ERDHRFG[, rgp/cnffjq, onfr64_, wninfpevcg:, ../, 127.0.0.1, vachg_svyr, grzc00, 70ork, pbasvtonx, qbzcqs, svyrargjbexf, wnung, xperj, xrljbeqfcl, zbovdhb, arffhf, enperj, ybphf7, ovgevk, zfbssvpr, puvyq_grezvangr, pbapng, nyybj_hey_sbcra, nyybj_hey_vapyhqr, nhgb_cercraq_svyr, oyrkobg, oebjfrefcybvg, p99, qvfnoyr_shapgvba, qbphzrag_ebbg, rynfgvk, rapbqrhevpbz, spybfr, strgf, schgf, sernq, sfohss, sfbpxbcra, trgubfgolanzr, tenoybtva, uzrv7, bcra_onfrqve, cnffgueh, cbcra, cebp_bcra, dhvpxoehgr, fnsr_zbqr, furyy_rkrp, fhk0e, kregvir, <fpevcg, sbcra, .cuc.vap, zbfpbasvt, zxqve, ezqve, puqve, pxsvaqre, shyypyvpx, spxrqvgbe, gvzguhzo, nofbyhgr_qve, nofbyhgr_cngu, ebbg_qve, ebbg_cngu, onfrqve, onfrcngu, ybbconpx, %00, 0k00, %0q%0n' )
			);
}

/**
 * Get contents forbidden in REMOTE_HOST by default.
 *
 * @since 1.4.9
 * @since 1.4.9.5 Use str_rot13 to prevent false positive from external tools/scanners
 *
 * @return (string) A comma-separated list.
 */
function secupress_firewall_bbq_host_content_bad_contents_list_default() {
	return  apply_filters( 'secupress.bad_host_contents.list',
			str_rot13( '163qngn, nznmbanjf, pbybpebffvat, pevzrn, t00t1r, whfgubfg, xnantnjn, ybbcvn, znfgreubfg, bayvarubzr, cbarlgry, fcevagqngnpragre, erirefr.fbsgynlre, fnsrarg, ggarg, jbbqcrpxre, jbjenpx' )
			);
}

/**
 * Get contents forbidden in HTTP_REFERER by default.
 *
 * @since 1.4.9
 * @since 1.4.9.5 Use str_rot13 to prevent false positive from external tools/scanners
 *
 * @return (string) A comma-separated list.
 */
function secupress_firewall_bbq_referer_content_bad_contents_list_default() {
	return  apply_filters( 'secupress.bad_referer_contents.list',
			str_rot13( 'frznyg.pbz, gbqncresrvgn, nzovra, oyhr fcvyy, pvnyvf, pbpnvar, rwnphyng, rerpgvyr, rerpgvbaf, ubbqvn, uhebaevirenperf, vzcbgrapr, yrivgen, yvovqb, yvcvgbe, curagrezva, fnaqlnhre, genznqby, geblunzol, hygenz, havpnhpn, inyvhz, ivnten, ivpbqva, knank, lcknvrb' )
			);
}


/** --------------------------------------------------------------------------------------------- */
/** OTHER ======================================================================================= */
/** --------------------------------------------------------------------------------------------- */

/**
 * See secupress_block_bad_url_contents
 *
 * @since 1.4.9
 * @author Juio Potier
 * @param (string) $function Short string to be concat to form the callback
 * @param (string) $server The index in $_SERVER to be checked
 * @param (string) $block_id Which code use if we block
 * @return (void)
 **/
function secupress_block_bad_content_but_what( $function, $server, $block_id ) {
	if ( ! isset( $_SERVER[ $server ] ) ) {
		return;
	}

	// don't block if our own domain name contains a bad word and is present in the URL (with redirect for example).
	$check_value  = str_replace( $_SERVER['HTTP_HOST'], '', $_SERVER[ $server ] );
	$check_value  = explode( '?', $check_value, 2 );
	// Nothing like a request uri? It's ok, don't look into the URLs paths
	if ( 'QUERY_STRING' !== $server && ! isset( $check_value[1] ) ) {
		return;
	}
	$check_value  = end( $check_value );
	$bad_contents = "secupress_firewall_bbq_{$function}_content_bad_contents_list_default";
	if ( ! function_exists( $bad_contents ) ) {
		wp_die( __FUNCTION__ ); // Should not happen in live.
	}
	$bad_contents = $bad_contents();

	if ( ! empty( $bad_contents ) ) {
		$bad_contents = preg_replace( '/\s*,\s*/', '|', preg_quote( $bad_contents, '/' ) );
		$bad_contents = trim( $bad_contents, '| ' );

		while ( false !== strpos( $bad_contents, '||' ) ) {
			$bad_contents = str_replace( '||', '|', $bad_contents );
		}
	}

	preg_match( '/' . $bad_contents . '/i', $check_value, $matches );
	if ( ! empty( $check_value ) && $bad_contents && ! empty( $matches ) ) {
		secupress_block( $block_id, [ 'code' => 503, 'b64' => [ 'data' => $matches ] ] );
	}

}

add_filter( 'secupress_block_id', 'secupress_firewall_block_id' );
/**
 * Translate block IDs into understandable things.
 *
 * @since 1.1.4
 * @since 1.4.9 BHC, BRC
 * @author Grégory Viguier
 *
 * @param (string) $module The related module.
 *
 * @return (string) The block ID.
 */
function secupress_firewall_block_id( $module ) {
	$block_ids = array(
		// Antispam.
		'AAU'  => __( 'Antispam, Anti-Usurpation', 'secupress' ),
		// URL Contents.
		'BUC'  => __( 'Bad URL Contents', 'secupress' ),
		'BHC'  => __( 'Bad Host Contents', 'secupress' ),
		'BRC'  => __( 'Bad Referer Contents', 'secupress' ),
		// GeoIP.
		'GIP'  => __( 'Bad GeoIP', 'secupress' ),
		// Request Method.
		'RMHM' => __( 'Bad Request Method', 'secupress' ),
		// User-Agent.
		'UAHT' => __( 'User-Agent With HTML Tags', 'secupress' ),
		'UAHB' => __( 'User-Agent Blacklisted', 'secupress' ),
	);

	return isset( $block_ids[ $module ] ) ? $block_ids[ $module ] : $module;
}
