import requests
from bs4 import BeautifulSoup

from notetool.download.m3u8 import m3u8Dataset
from notetool.tool import decrypt
from notetool.tool import log

logger = log('download')


def parse_url_pages(pages=None, save_path=''):
    cookies = {
        'nlbi_764880': '109sEf9aoSzt3uQBoEMXnQAAAAD6XZGeY+jpIiJ7/bXcdLNz',
        'visid_incap_764880': 'Z902BXZzSymLeRzR5XOIB0NkN14AAAAAQUIPAAAAAACkkmJ9s6ND94BPNAEZC0Nb',
        'incap_ses_724_764880': 'CMf7K2PNLFMUmJ7DSisMCkNkN14AAAAALsjYhWggJ5k07TTico7KiQ==',
        '_ga': 'GA1.2.311422892.1580688460',
        '_gid': 'GA1.2.952932010.1580688460',
        'A8tI_2132_saltkey': 'EXCzrNCk',
        'A8tI_2132_lastvisit': '1580685451',
        'A8tI_2132_lastact': '1580689170%09forumthread.php%09',
        'A8tI_2132_mapiurl': 'https%3A%2F%2Fim01_prod_mserver.motesiji.info%2F',
        'A8tI_2132_adv_gid': '7',
        'A8tI_2132_st_t': '0%7C1580689118%7Cd3df1c073775c40c443c7205d3dbae7e',
        'A8tI_2132_atarget': '1',
        'A8tI_2132_forum_lastvisit': 'D_708_1580689118',
        'A8tI_2132_visitedfid': '708',
        'incap_ses_882_764880': 'gv4oIYeBzgRyC/AtT389DJpmN14AAAAAmMRGtq9outJSD9s/k6jtMw==',
        'A8tI_2132_self_uid': '-1',
        'A8tI_2132_self_fid': '708',
        'A8tI_2132_self_tid': '11964033',
        'A8tI_2132_self_unique_code': '60234657-a76d-1d2a-2070-bf54c11c3563',
        'cus_cookie': '11',
        'A8tI_2132_ignore_notice': '1',
        'A8tI_2132_lt_ad_1': '1',
        'A8tI_2132_st_p': '0%7C1580689154%7C4f073b76b6de72d0b341ec74bb3b2ce4',
        'A8tI_2132_viewid': 'tid_11964033',
        'A8tI_2132_V_videoFloat': '1',
    }

    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:72.0) Gecko/20100101 Firefox/72.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    }

    def get_url(tid):
        params = (
            ('mod', 'viewthread'),
            ('tid', tid),
            ('extra', 'page=1&filter=heat&orderby=heats'),
        )
        url = decrypt(b'gAAAAABeQTmG5eFv4h19N2TwrU50y4cEQVr2ImBSV159qaEIYeRssgg0S6hrFYMgrVns-'
                      b'i7pwxJg0CL6W-6SYVFbgUYeSK5fm6x9CCO70rHX4XNbBV-eyJm0eWruPLPaeVOWGZznwbD0')
        response = requests.get(url,
                                headers=headers,
                                params=params,
                                cookies=cookies,
                                timeout=60)

        soup = BeautifulSoup(response.text, features="lxml")

        urls = soup.findAll(name="div", attrs={"class": "playerWrap ckplayerPlugin"})
        if len(urls) > 0:
            url = urls[0]
            return url.attrs['data-high']

    if pages is None:
        pages = [1, 10]

    index = 0
    m3u8 = m3u8Dataset(db_path=save_path)
    for page in pages:
        params = (('mod', 'forumdisplay'),
                  ('fid', '708'),
                  ('orderby', ['heats', 'heats']),
                  ('filter', 'heat'),
                  ('page', page))
        url = decrypt(b'gAAAAABeQTmG5eFv4h19N2TwrU50y4cEQVr2ImBSV159qaEIYeRssgg0S6hrFYMgrVns-'
                      b'i7pwxJg0CL6W-6SYVFbgUYeSK5fm6x9CCO70rHX4XNbBV-eyJm0eWruPLPaeVOWGZznwbD0')
        response = requests.get(url,
                                headers=headers,
                                params=params,
                                cookies=cookies,
                                timeout=60)
        soup = BeautifulSoup(response.text, features="lxml")
        urls = soup.findAll(name="a", attrs={"class": "s xst"})

        for url in urls:
            href = url.attrs['href']
            print('{}-{} {}'.format(page, index, href))

            if 'thread-' in href:
                tid = href.split('-')[1]
            elif 'tid' in url.attrs['href']:
                tid = url.attrs['href'].split('tid=')[1].split('&')[0]
            else:
                continue
            if tid == 0:
                continue

            if m3u8.exists(param1=str(tid)):
                continue

            index += 1
            try:
                m3u8.insert(url=get_url(tid), name=url.text, param1=tid)
            except Exception as e:
                print(e)
    return m3u8
