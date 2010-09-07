#! /usr/bin/env python

import xml.dom.minidom
import os
import stat
import re
from cStringIO import StringIO
import sys

import ezt

base_template = ezt.Template()
base_template.parse(file('templates/base.ezt').read())
buildlog_template = ezt.Template()
buildlog_template.parse(file('templates/buildlog.ezt').read())
changelog_template = ezt.Template()
changelog_template.parse(file('templates/changelog.ezt').read())
tests_template = ezt.Template()
tests_template.parse(file('templates/tests.ezt').read())

def getText(nodelist):
    if not nodelist:
        return None
    rc = ''
    for node in nodelist:
        if node.nodeType == node.TEXT_NODE:
            rc = rc + node.data
    return rc.encode('utf-8')


class ChangelogFile:
    def __init__(self, node):
        for attr in ('name', 'revision'):
            try:
                setattr(self, attr, getText(node.getElementsByTagName(attr)[0].childNodes))
            except IndexError:
                setattr(self, attr, None)


class ChangelogEntry:
    def __init__(self, node):
        for attr in ('date', 'weekday', 'time', 'isoDate', 'msg', 'author', 'revision'):
            try:
                setattr(self, attr, getText(node.getElementsByTagName(attr)[0].childNodes))
            except IndexError:
                setattr(self, attr, None)
        self.file = [ChangelogFile(x) for x in node.getElementsByTagName('file')]

class ChangelogSvnEntry:
    def __init__(self, node):
        for attr in ('date', 'msg', 'author', 'file'):
            try:
                setattr(self, attr, getText(node.getElementsByTagName(attr)[0].childNodes))
            except IndexError:
                setattr(self, attr, None)
        self.revision = node.attributes['revision'].value
        if self.date:
            self.time = self.date[11:16]


class TestTest:
    def __init__(self, node):
        for attr in ('id', 'description'):
            try:
                setattr(self, attr, getText(node.getElementsByTagName(attr)[0].childNodes))
            except IndexError:
                setattr(self, attr, None)
        self.result = node.attributes['result'].value

class TestSuite:
    def __init__(self, node):
        for attr in ('title', 'duration'):
            try:
                setattr(self, attr, getText(node.getElementsByTagName(attr)[0].childNodes))
            except IndexError:
                setattr(self, attr, None)
        if self.duration:
            self.duration = '%.4f' % float(self.duration)
        self.test = [TestTest(x) for x in node.getElementsByTagName('test')]
        self.len_tests = len(self.test)


class Build:
    def __init__(self, node):
        for attr in ('date', 'hostname', 'duration', 'buildlog', 'buildlog295', 'changelog'):
            try:
                setattr(self, attr, getText(node.getElementsByTagName(attr)[0].childNodes))
            except IndexError:
                setattr(self, attr, None)

        self.display_date = '%s-%s-%s' % (self.date[:4], self.date[4:6], self.date[6:8])
        self.display_hour = '%s:%s' % (self.date[9:11], self.date[11:13])

        for component in ('liblasso', 'java', 'python', 'php', 'perl', 'csharp', 'liblasso295'):
            try:
                cnode = [x for x in node.getElementsByTagName(component) if \
                        x.attributes.has_key('buildlog')][0]
            except IndexError:
                setattr(self, component + '_status', None)
                continue
            setattr(self, component + '_status', getText(cnode.childNodes))
            setattr(self, component + '_href', cnode.attributes['buildlog'].value.replace('.xml',''))

        for test in ('c', 'python', 'souk'):
            try:
                cnode = [x for x in node.getElementsByTagName(test) if \
                        x.attributes.has_key('href')][0]
            except IndexError:
                setattr(self, 'tests_' + test + '_status', None)
                continue
            setattr(self, 'tests_' + test + '_status', getText(cnode.childNodes))
            setattr(self, 'tests_' + test + '_href', cnode.attributes['href'].value.replace('.xml', ''))

        if self.changelog:
            self.changelog = self.changelog.replace('.xml', '')
            try:
                dom_cl = xml.dom.minidom.parse(file('web' + self.changelog + '.xml'))
            except:
                self.nb_commits = '?'
                self.last_commit_author = '?'
            else:
                self.last_commit_author = getText(dom_cl.getElementsByTagName('author')[-1].childNodes)
                self.nb_commits = len(dom_cl.getElementsByTagName('entry'))
                if not self.nb_commits:
                    self.nb_commits = len(dom_cl.getElementsByTagName('logentry'))



re_body = re.compile('<body(.*?)>(.*)</body>', re.DOTALL)
re_div = re.compile('<div(.*?)>(.*)</div>', re.DOTALL)
re_title = re.compile('<title>(.*)</title>', re.DOTALL)
re_summary = re.compile('[a-z]+\.[0-9]{4}.xml')

if not os.path.exists('web-static'):
    os.mkdir('web-static')

for BUILDLOGS_DIR in ('build-logs', 'build-logs-wsf'):
    if not os.path.exists('web/%s' % BUILDLOGS_DIR):
        continue
    if not os.path.exists('web-static/%s' % BUILDLOGS_DIR):
        os.mkdir('web-static/%s' % BUILDLOGS_DIR)

    for base, dirs, files in os.walk('web/%s' % BUILDLOGS_DIR):
        if base.endswith('/CVS') or base.endswith('/.svn') or base.endswith('/.git'):
            continue
        for dirname in dirs:
            src_file = os.path.join(base, dirname)
            dst_file = 'web-static/' + src_file[4:]
            if not os.path.exists(dst_file):
                os.mkdir(dst_file)
        for filename in files:
            if filename[0] == '.':
                continue
            src_file = os.path.join(base, filename)
            dst_file = 'web-static/' + src_file[4:].replace('.xml', '.html')
            if os.path.exists(dst_file) and \
                    os.stat(dst_file)[stat.ST_MTIME] >= os.stat(src_file)[stat.ST_MTIME]:
                continue
            if src_file.endswith('.log'):
                os.link(src_file, dst_file)
                continue
            if src_file.endswith('.html'):
                try:
                    body = re_body.findall(file(src_file).read())[0][1].strip()
                except IndexError:
                    raise "no body found"
                fd = StringIO()
                base_template.generate(fd, {'body': body, 'title': 'Build Log', 'section': 'buildbox'})
                open(dst_file, 'w').write(fd.getvalue())
                continue

            try:
                dom = xml.dom.minidom.parse(file(src_file))
            except:
                continue
            type = dom.childNodes[0].nodeName
            if type == 'changelog':
                entries = [ChangelogEntry(x) for x in dom.getElementsByTagName('entry')]
                fd = StringIO()
                changelog_template.generate(fd, {'entry': entries})
                body = fd.getvalue()
                fd = StringIO()
                base_template.generate(fd, {'body': body, 'title': 'ChangeLog', 'section': 'buildbox'})
                open(dst_file, 'w').write(fd.getvalue())

            if type == 'log':
                entries = [ChangelogSvnEntry(x) for x in dom.getElementsByTagName('logentry')]
                fd = StringIO()
                changelog_template.generate(fd, {'entry': entries})
                body = fd.getvalue()
                fd = StringIO()
                base_template.generate(fd, {'body': body, 'title': 'ChangeLog', 'section': 'buildbox'})
                open(dst_file, 'w').write(fd.getvalue())

            if type == 'testsuites':
                datetime = getText(dom.getElementsByTagName('datetime')[0].childNodes)
                title = getText(dom.getElementsByTagName('title')[0].childNodes)
                suites = [TestSuite(x) for x in dom.getElementsByTagName('suite')]
                fd = StringIO()
                tests_template.generate(fd, {'datetime': datetime, 'title': title,
                        'suite': suites})
                body = fd.getvalue()
                fd = StringIO()
                base_template.generate(fd, {'body': body,
                        'title': 'Test Suite - %s' % title, 'section': 'buildbox'})
                open(dst_file, 'w').write(fd.getvalue())


    day_dirs = os.listdir('web/%s/' % BUILDLOGS_DIR)
    day_dirs.sort()
    day_dirs.reverse()
    day_dirs = day_dirs[:60]

    main_page = []

    for base, dirs, files in os.walk('web/%s' % BUILDLOGS_DIR):
        for dirname in dirs:
            if dirname in day_dirs:
                for t in [x for x in os.listdir(os.path.join(base, dirname)) if re_summary.match(x)]:
                    main_page.append(os.path.join(base, dirname, t))

    main_page.sort()
    main_page.reverse()
    main_page = main_page[:50]
    builds = []
    for filename in main_page:
        try:
            builds.append( Build(xml.dom.minidom.parse(filename)) )
            if len(builds) > 1 and builds[-2].date[:8] == builds[-1].date[:8]:
                builds[-1].display_date = ''
        except:
            pass

    fd = StringIO()
    buildlog_template.generate(fd, {'build': builds})
    body = fd.getvalue()
    fd = StringIO()
    base_template.generate(fd, {'body': body, 'title': 'Build Box', 'section': 'buildbox'})
    if BUILDLOGS_DIR == 'build-logs':
        open('web-static/buildbox.html', 'w').write(fd.getvalue())
    elif BUILDLOGS_DIR == 'build-logs-wsf':
        open('web-static/buildbox-wsf.html', 'w').write(fd.getvalue())

for base, dirs, files in os.walk('web'):
    if '/build-logs' in base or '/news/' in base:
        continue
    if base.endswith('CVS') or base.endswith('.svn'):
        continue
    for dirname in dirs:
        if dirname in ('CVS', 'news', '.svn'):
            continue
        src_file = os.path.join(base, dirname)
        dst_file = 'web-static/' + src_file[4:]
        if not os.path.exists(dst_file):
            os.mkdir(dst_file)
    for filename in files:
        if filename in ('.cvsignore', 'buildbox.xml'):
            continue
        if filename[0] == '.':
            continue
        basename, ext = os.path.splitext(filename)
        src_file = os.path.join(base, filename)
        dst_file = 'web-static/' + src_file[4:]

        if os.path.isdir(src_file): continue

        if os.path.exists(dst_file) and \
                os.stat(dst_file)[stat.ST_MTIME] >= os.stat(src_file)[stat.ST_MTIME]:
            continue

        if ext not in ('.html', '.xml') or filename.startswith('doap.') or 'api-reference' in src_file:
            if os.path.exists(dst_file):
                os.unlink(dst_file)
            os.link(src_file, dst_file)
            continue

        type = None
        if ext == '.xml':
            dom = xml.dom.minidom.parse(file(src_file))
            type = dom.childNodes[0].nodeName
            dst_file = dst_file.replace('.xml', '.html')

        news = None
        if dst_file == 'web-static/index.html':
            news_files = [x for x in os.listdir('web/news/') if x.endswith('.xml') and x[2] == '-']
            news_files.sort()
            news_files.reverse()
            news_files = news_files[:3]
            news = []
            for f in news_files:
                news.append('<div>%s</div>' % re_div.findall(file(os.path.join('web/news/', f)).read())[0][1].strip())
            news = '\n'.join(news)

        section = src_file.split('/')[1].replace('.xml', '')
        if ext == '.html' or type == 'html':
            content = file(src_file).read()
            try:
                body = re_body.findall(content)[0][1].strip()
            except IndexError:
                raise "no body found"
            title = re_title.findall(content)[0]
            fd = StringIO()
            base_template.generate(fd, {'body': body, 'title': title, 'section': section,
                    'news': news})
            open(dst_file, 'w').write(fd.getvalue())
            continue

