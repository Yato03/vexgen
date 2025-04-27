import React, { createContext, useContext, useState } from 'react'
import PropTypes from 'prop-types'
import { useNavigate, Link } from 'react-router-dom'
import { ChevronFirst, ChevronLast } from 'lucide-react'
import vexgenLogo from '../assets/vexgenLogo.png'
import vexgenCompleteLogo from '../assets/vexgenCompleteLogo.png'
import Button from '@mui/material/Button'

const SidebarContext = createContext()

export default function Sidebar({ is_logged, children }) {
  const [expanded, set_expanded] = useState(true)
  const navigate = useNavigate()

  const on_button_logout_click = () => {
    localStorage.removeItem('access_token')
    localStorage.removeItem('user_id')
    navigate('/')
    window.location.reload()
  }

  const on_click_navigate_home = () => {
    navigate('/')
  }

  return (
    <>
      <aside>
        <nav className='h-full flex flex-col bg-white border-r shadow-sm'>
          <div className='p-4 flex items-start justify-between'>
            {
              expanded ?
              <img src={vexgenCompleteLogo} alt='' onClick={() => on_click_navigate_home()} className='overflow-hidden transition-all w-28 cursor-pointer'/> :
              <img src={vexgenLogo} alt='' onClick={() => on_click_navigate_home()} className='overflow-hidden transition-all w-12 cursor-pointer'/>
            }
            <button onClick={() => set_expanded((curr) => !curr)} className='p-1.5 rounded-lg bg-gray-50 hover:bg-gray-100'>
              {expanded ? <ChevronFirst /> : <ChevronLast />}
            </button>
          </div>

          <SidebarContext.Provider value={{ expanded }}>
            <ul className='flex-1 px-3'>{children}</ul>
          </SidebarContext.Provider>

          <div className='pb-2 pl-4 pr-4'>
            {is_logged ? (
              <Button variant="contained" style={{backgroundColor: "#d97706"}} size="small" onClick={on_button_logout_click}>Log out</Button>
            ) : null}
          </div>
          <div className={`transition-all overflow-hidden ${expanded ? 'border-t flex p-3' : 'w-0 h-0'}`}>
            <div className='flex justify-between items-center w-52 ml-3'>
              <div className='leading-4'>
                <h4 className='font-semibold text-xs text-gray-600'>
                  {' '}
                  VEXGen is sponsored by{' '}
                  <a className='underline' href='https://www.us.es/'>
                    University of Seville
                  </a>{' '}
                  &{' '}
                  <a className='underline' href='http://www.idea.us.es/'>
                    IDEA Research Group
                  </a>
                </h4>
                <span className='text-xs text-gray-600'>amtrujillo@us.es</span>
              </div>
            </div>
          </div> 
        </nav>
      </aside>
    </>
  )
}

Sidebar.propTypes = {
  is_logged: PropTypes.bool,
  children: PropTypes.array
}

export function SidebarItem({ icon, text, active, alert, route, outside = false}) {
  const { expanded } = useContext(SidebarContext)
  return (
    <li
      className={`relative flex items-center py-2 px-3 my-1 font-medium rounded-md cursor-pointer transition-colors group ${active ? 'bg-gradient-to-tr from-amber-200 to-amber-100 text-amber-800' : 'hover:bg-amber-50 text-gray-600'}`}
    >
      { outside ? (
        <a
          className='relative flex items-center py-2 px-3 my-1 font-medium rounded-md cursor-pointer transition-colors group'
          href={route}
          target='_blank'
          rel='noopener noreferrer'
        >
          {icon}
          <span className={`overflow-hidden transition-all ${expanded ? 'w-36 ml-3' : 'w-0'}`}>{text}</span>
        </a>
      ) : (
        <Link
          className='relative flex items-center py-2 px-3 my-1 font-medium rounded-md cursor-pointer transition-colors group'
          to={route}
        >
          {icon}
          <span className={`overflow-hidden transition-all ${expanded ? 'w-36 ml-3' : 'w-0'}`}>{text}</span>
        </Link>)
      }
      {alert && <div className={`absolute right-2 w-2 h-2 rounded bg-amber-400 ${expanded ? '' : 'top-2'}`}></div>}
      {!expanded && (
        <div
          className={`absolute left-full rounded-md px-2 py-1 ml-6 bg-amber-100 text-amber-800 text-sm invisible opacity-20 -translate-x-3 transition-all group-hover:visible group-hover:opacity-100 group-hover:translate-x-0`}
        >
          {text}
        </div>
      )}
    </li>
  )
}

SidebarItem.propTypes = {
  icon: PropTypes.object,
  text: PropTypes.string,
  active: PropTypes.bool,
  alert: PropTypes.bool,
  route: PropTypes.string,
  outside: PropTypes.bool
}
