import html.parser
import sys, time

outputFile = open('./9j20911292ao1.txt', 'w')
def output(s):
	outputFile.write(s + '\n')

supportedOS = \
{
	'XP' : 'Windows XP',
	'VISTA' : 'Windows Vista',
	'WIN7' : 'Windows 7',
	'WIN8' : 'Windows 8',
	'WIN81' : 'Windows 8.1'
}
supportedSP = \
{
	'XP' : [0, 1, 2, 3],
	'VISTA' : [0, 1, 2],
	'WIN7' : [0, 1],
	'WIN8' : [0],
	'WIN81' : [0]
}
tables = \
{
	'XP' : [], 'VISTA' : [], 'WIN7' : [], 'WIN8' : [], 'WIN81' : []
}
for osName in supportedOS:
	for _ in range(1 + max(supportedSP[osName])):
		tables[osName].append([])

class MyParser(html.parser.HTMLParser):
	def __init__(self):
		super().__init__()
		self.rowNumber = (-1)
		self.colNumber = (-1)
		self.colNames = []
		self.colCounts = []
		self.colSP = {}
		self.newCol = False
		self.dataList = []

	# quick diagnostic
	def Diag(self):
		for name in self.colNames:
			print(name)
			if self.hasSP:
				print(self.colSP[name])
			# for syscall in self.dataList:
			# 	print(syscall)

	def GetIndex(self, osName, osSP):
		colName = supportedOS[osName]
		colIndex = self.colNames.index(colName)
		if colIndex == -1:
			raise Exception()
		index = 0
		if colIndex > 0:
			for count in self.colCounts[:colIndex]:
				index += count
		spList = self.colSP[colName]
		spNumbers = sorted([int(sp[2]) for sp in spList])
		for spNum in spNumbers:
			if spNum != osSP:
				index += 1
			else:
				break
		return index
	def Process(self, osName, osSP, target):
		index = self.GetIndex(osName, osSP)
		for syscall in self.dataList:
			callName = syscall[0]
			callNumber = syscall[index+1]
			target.append([callNumber, callName])
	def ProcessData(self):
		for osName in supportedOS:
			for osSP in supportedSP[osName]:
				target = tables[osName][osSP]
				self.Process(osName, osSP, target)

	def NewRow(self, attrs):
		self.rowNumber += 1
		self.colNumber = -1
		self.newCol = False

	def NewCol(self, attrs):
		self.colNumber += 1
		d = dict(attrs)

		# Height of (0,0) cell determines if the table has service packs
		if self.rowNumber == 0 and self.colNumber == 0:
			if 'rowspan' in d and int(d['rowspan']) == 2:
				self.hasSP = True
			else:
				self.hasSP = False
		# Number of service packs per OS version
		elif self.rowNumber == 0:
			if 'colspan' in d:
				self.colCounts.append(int(d['colspan']))
			else:
				self.colCounts.append(1)

		self.newCol = True

	def NewData(self, data):
		if not self.newCol:
			return
		else:
			self.newCol = False

		# (0,0) cell
		if self.rowNumber == 0 and self.colNumber == 0:
			pass
		# OS versions
		elif self.rowNumber == 0 and self.colNumber > 0:
			self.colNames.append(data.strip())
		# OS service packs
		elif self.rowNumber == 1 and self.hasSP:
			prevCount = len([val for key in self.colSP for val in self.colSP[key]])
			index = -1
			for q in range(len(self.colCounts)):
				index = q
				if prevCount >= self.colCounts[q]:
					prevCount -= self.colCounts[q]
				else:
					break
			if self.colNames[index] not in self.colSP:
				self.colSP[self.colNames[index]] = []
			if data.strip() == '8.0':
				self.colSP[self.colNames[index]].append('SP0')
			elif data.strip() != '8.1':
				self.colSP[self.colNames[index]].append(data.strip())
			else:
				# special case Windows 8.1
				self.colCounts[index] -= 1
				self.colNames.append('Windows 8.1')
				self.colCounts.append(1)
				self.colSP['Windows 8.1'] = ['SP0']
		# Syscall name
		elif self.colNumber == 0:
			self.dataList.append([])
			self.dataList[-1].append(data.strip())
		# Syscall numbers
		else:
			if data.strip() == '':
				self.dataList[-1].append(-1)
			else:
				self.dataList[-1].append(int(data.strip(), 16))

	def handle_starttag(self, tag, attrs):
		if tag == 'tr':
			self.NewRow(attrs)
		elif tag == 'td':
			self.NewCol(attrs)

	def handle_data(self, data):
		self.NewData(data)

def GetHtmlStr(path):
	with open(path, 'r') as f:
		return f.read().strip()

ntparser = MyParser()
winparser = MyParser()

nthtml = GetHtmlStr('jooru_files/nt32.html')
winhtml = GetHtmlStr('jooru_files/win32.html')
ntparser.feed(nthtml)
ntparser.ProcessData()
winparser.feed(winhtml)
winparser.ProcessData()

table = tables['XP'][3]
for entry in table:
	print(entry[0], entry[1])