import React, { useState, useEffect } from 'react'
import { useNavigate } from "react-router-dom"
import PropTypes from 'prop-types'
import { Eye, ArrowBigDownDash, ArrowBigUpDash } from 'lucide-react'
import { useTheme } from '@mui/material/styles'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import MenuItem from '@mui/material/MenuItem'
import Select from '@mui/material/Select'
import Table from '@mui/material/Table'
import TableBody from '@mui/material/TableBody'
import TableCell from '@mui/material/TableCell'
import TableContainer from '@mui/material/TableContainer'
import TableHead from '@mui/material/TableHead'
import TableRow from '@mui/material/TableRow'
import TableFooter from '@mui/material/TableFooter'
import TablePagination from '@mui/material/TablePagination'
import Paper from '@mui/material/Paper'
import IconButton from '@mui/material/IconButton'
import FirstPageIcon from '@mui/icons-material/FirstPage'
import KeyboardArrowLeft from '@mui/icons-material/KeyboardArrowLeft'
import KeyboardArrowRight from '@mui/icons-material/KeyboardArrowRight'
import LastPageIcon from '@mui/icons-material/LastPage'

function TablePaginationActions(props) {
  const theme = useTheme()
  const { count, page, rowsPerPage, onPageChange } = props

  const handleFirstPageButtonClick = (event) => {
    onPageChange(event, 0)
  }

  const handleBackButtonClick = (event) => {
    onPageChange(event, page - 1)
  }

  const handleNextButtonClick = (event) => {
    onPageChange(event, page + 1)
  }

  const handleLastPageButtonClick = (event) => {
    onPageChange(event, Math.max(0, Math.ceil(count / rowsPerPage) - 1))
  }

  return (
    <Box sx={{ flexShrink: 0, ml: 2.5 }}>
      <IconButton
        onClick={handleFirstPageButtonClick}
        disabled={page === 0}
        aria-label="first page"
      >
        {theme.direction === 'rtl' ? <LastPageIcon /> : <FirstPageIcon />}
      </IconButton>
      <IconButton
        onClick={handleBackButtonClick}
        disabled={page === 0}
        aria-label="previous page"
      >
        {theme.direction === 'rtl' ? <KeyboardArrowRight /> : <KeyboardArrowLeft />}
      </IconButton>
      <IconButton
        onClick={handleNextButtonClick}
        disabled={page >= Math.ceil(count / rowsPerPage) - 1}
        aria-label="next page"
      >
        {theme.direction === 'rtl' ? <KeyboardArrowLeft /> : <KeyboardArrowRight />}
      </IconButton>
      <IconButton
        onClick={handleLastPageButtonClick}
        disabled={page >= Math.ceil(count / rowsPerPage) - 1}
        aria-label="last page"
      >
        {theme.direction === 'rtl' ? <FirstPageIcon /> : <LastPageIcon />}
      </IconButton>
    </Box>
  )
}

TablePaginationActions.propTypes = {
  count: PropTypes.number.isRequired,
  onPageChange: PropTypes.func.isRequired,
  page: PropTypes.number.isRequired,
  rowsPerPage: PropTypes.number.isRequired,
}


const VEXsPage = () => {
  const [owner, set_owner] = useState('')
  const [name, set_name] = useState('')
  const [sbom_path, set_sbom_path] = useState('')
  const [statements_group, set_statements_group] = useState('no_grouping')
  const [owner_error, set_owner_error] = useState('')
  const [name_error, set_name_error] = useState('')
  const [sbom_path_error, set_sbom_path_error] = useState('')
  const [vexs, set_vexs] = useState([])
  const [page, setPage] = React.useState(0)
  const [rowsPerPage, setRowsPerPage] = React.useState(5)
  const [message, set_message] = useState("")
  const navigate = useNavigate()
  const emptyRows = page > 0 ? Math.max(0, (1 + page) * rowsPerPage - vexs.length) : 0

  const handleChangePage = (event, newPage) => {
    setPage(newPage)
  }

  const handleChangeRowsPerPage = (event) => {
    setRowsPerPage(parseInt(event.target.value, 10))
    setPage(0)
  }

  useEffect(() => {
    const access_token = localStorage.getItem('access_token')
    const user_id = localStorage.getItem('user_id')
    const fetch_vexs= () => {
      fetch('http://localhost:8000/vex/user/' + user_id, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${access_token}`
        }
      })
        .then((r) => r.json())
        .then((r) => {
          set_vexs(r)
        })
    }
    fetch_vexs()
    const intervalId = setInterval(fetch_vexs, 10000)
    return () => clearInterval(intervalId)
  }, [])

  const on_button_generate_vex = () => {
    set_owner_error('')
    set_name_error('')
    set_sbom_path_error('')

    if ('' === owner) {
      set_owner_error('Please enter a owner')
      return
    }

    if ('' === name) {
      set_name_error('Please enter a name')
      return
    }

    if ('' === sbom_path) {
      set_sbom_path_error('Please enter a sbom path')
      return
    }

    set_message("The VEX is being generated!")

    setTimeout(() => {
      set_message("")
    }, 5000)

    const user_id = localStorage.getItem('user_id')

    fetch('http://localhost:8000/vex/generate', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ owner, name, sbom_path, statements_group, user_id })
    })
  }

  const handle_statements_group_change = (event) => {
    set_statements_group(event.target.value)
  }

  const download_vex = (vex_id) => {
    fetch('http://localhost:8000/vex/download/' + vex_id, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      }
    })
      .then(async response => {
        const disposition = response.headers.get('Content-Disposition')
        var filename = disposition.split(/;(.+)/)[1].split(/=(.+)/)[1]
        if (filename.toLowerCase().startsWith("utf-8''"))
          filename = decodeURIComponent(filename.replace("utf-8''", ''))
        else
          filename = filename.replace(/['"]/g, '')
        var url = window.URL.createObjectURL(await response.blob())
        var a = document.createElement('a')
        a.href = url
        a.download = filename
        document.body.appendChild(a)
        a.click()
        a.remove()
      })
  }

  const ingest_vex = (vex_id) => {

    set_message("The VEX is being ingested by GUAC!")

    setTimeout(() => {
      set_message("")
    }, 5000)

    fetch('http://localhost:8000/vex/ingest/' + vex_id, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      }
    })
      .then(async response => {
        const data = await response.json()
        console.log(data)
      })
      .catch(error => {
        console.error('Error al ingestar el VEX:', error)
      })
  }

  const show_vex = (vex_id) => {
    navigate('/vex/' + vex_id)
  }

  return (
    <div className='flex flex-col h-screen justify-center items-center m-auto space-y-4 w-8/12'>
      <p className='text-lg font-normal text-gray-500 lg:text-xl sm:px-16 xl:px-48 dark:text-gray-400 text-center'>
        You must enter here the owner, name and the SBOM path in a public repository.
      </p>
      <div className='flex gap-4'>
        <input
          value={owner}
          type='text'
          placeholder='Enter the owner here'
          onKeyDown={(e) => {
            if (e.key === 'Enter') on_button_generate_vex()
          }}
          onChange={(ev) => set_owner(ev.target.value)}
          className='w-64 shadow appearance-none border rounded w-full py-2 px-2 text-gray-700 mb-3 leading-tight focus:outline-none focus:shadow-outline'
        />
        <input
          value={name}
          type='text'
          placeholder='Enter the name here'
          onKeyDown={(e) => {
            if (e.key === 'Enter') on_button_generate_vex()
          }}
          onChange={(ev) => set_name(ev.target.value)}
          className='w-64 shadow appearance-none border rounded w-full py-2 px-2 text-gray-700 mb-3 leading-tight focus:outline-none focus:shadow-outline'
        />
        <input
          value={sbom_path}
          type='text'
          placeholder='Enter the sbom path here'
          onKeyDown={(e) => {
            if (e.key === 'Enter') on_button_generate_vex()
          }}
          onChange={(ev) => set_sbom_path(ev.target.value)}
          className='w-64 shadow appearance-none border rounded w-full py-2 px-2 text-gray-700 mb-3 leading-tight focus:outline-none focus:shadow-outline'
        />

      </div>
      <Select value={statements_group} onChange={handle_statements_group_change}>
        <MenuItem value={'no_grouping'}>No Grouping</MenuItem>
        <MenuItem value={'supplier'}>Supplier</MenuItem>
        <MenuItem value={'attack_vector_av'}>Attack Vector AV</MenuItem>
        <MenuItem value={'attack_vector_ac'}>Attack Vector AC</MenuItem>
        <MenuItem value={'attack_vector_au'}>Attack Vector AU</MenuItem>
        <MenuItem value={'attack_vector_c'}>Attack Vector C</MenuItem>
        <MenuItem value={'attack_vector_i'}>Attack Vector I</MenuItem>
        <MenuItem value={'attack_vector_a'}>Attack Vector A</MenuItem>
        <MenuItem value={'reachable_code'}>Reachable Code</MenuItem>
      </Select>
      <label className={`text-red-600 ${owner_error !== '' ? '' : 'hidden'}`}>{owner_error}</label>
      <label className={`text-red-600 ${name_error !== '' ? '' : 'hidden'}`}>{name_error}</label>
      <label className={`text-red-600 ${sbom_path_error !== '' ? '' : 'hidden'}`}>{sbom_path_error}</label>
      <Button variant="contained" style={{backgroundColor: "#d97706"}} onClick={on_button_generate_vex}>Generate VEX</Button>
      <a 
            href="http://localhost:8080"
            className='flex items-center justify-center text-gray-500 border-2 rounded-lg p-2 hover:bg-gray-100'
            target="_blank" rel="noreferrer"
          >Visit GUAC GraphQL Playground</a>
      <label className={`text-green-300 bg-lime-100 pr-1 pl-1 rounded`}>{message}</label>
      <TableContainer component={Paper}>
        <Table sx={{ minWidth: 650 }} aria-label="simple table">
          <TableHead>
            <TableRow>
              <TableCell align="center">Owner</TableCell>
              <TableCell align="center">Name</TableCell>
              <TableCell align="center">SBOM Path</TableCell>
              <TableCell align="center">Show VEX</TableCell>
              <TableCell align="center">Download VEX</TableCell>
              <TableCell align="center">Ingest VEX in GUAC</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {(rowsPerPage > 0
              ? vexs.slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage)
              : vexs
            ).map((vex) => (
              <TableRow
                key={vex._id}
                sx={{ '&:last-child td, &:last-child th': { border: 0 } }}
              >
                <TableCell align="center">{vex.owner}</TableCell>
                <TableCell align="center">{vex.name}</TableCell>
                <TableCell align="center">{vex.sbom_path}</TableCell>
                <TableCell align="center"><Button size="small" variant="contained" style={{backgroundColor: "#d97706"}} onClick={() => show_vex(vex._id)}><Eye /></Button></TableCell>
                <TableCell align="center"><Button size="small" variant="contained" style={{backgroundColor: "#d97706"}} onClick={() => download_vex(vex._id)}><ArrowBigDownDash /></Button></TableCell>
                <TableCell align="center"><Button size="small" variant="contained" style={{backgroundColor: "#d97706"}} onClick={() => ingest_vex(vex._id)}><ArrowBigUpDash /></Button></TableCell>
              </TableRow>
            ))}
            {emptyRows > 0 && (
              <TableRow style={{ height: 53 * emptyRows }}>
                <TableCell colSpan={6} />
              </TableRow>
            )}
          </TableBody>
          <TableFooter>
            <TableRow>
              <TablePagination
                rowsPerPageOptions={[5, 10, 25, { label: 'All', value: -1 }]}
                colSpan={3}
                count={vexs.length}
                rowsPerPage={rowsPerPage}
                page={page}
                slotProps={{
                  select: {
                    inputProps: {
                      'aria-label': 'rows per page',
                    },
                    native: true,
                  },
                }}
                onPageChange={handleChangePage}
                onRowsPerPageChange={handleChangeRowsPerPage}
                ActionsComponent={TablePaginationActions}
              />
            </TableRow>
          </TableFooter>
        </Table>
      </TableContainer>
    </div>
  )
}

export { VEXsPage }
